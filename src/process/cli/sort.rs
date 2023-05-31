//! # Sort
//!
//! Sort rearranges the events so they are grouped by skb tracking id (or OVS queue_id if present)

use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::PathBuf,
};

use anyhow::{bail, Result};
use clap::Parser;

use crate::{
    cli::*,
    core::{
        events::{file::FileEventsFactory, EventFactory, EventResult},
        signals::Running,
    },
    module::Modules,
    process::{
        series::{EventSeries, EventSorter},
        tracking::AddTracking,
    },
};

/// The default size of the sorting buffer
const DEFAULT_BUFFER: usize = 1000;

/// Sort events in series based on tracking id.
///
/// Reads events from the INPUT file and arranges them by tracking id. The output is a number of
/// "event sets". An event set is a list of events that share the same tracking id (i.e: belong to
/// the same packet).
#[derive(Parser, Debug, Default)]
#[command(name = "sort")]
pub(crate) struct Sort {
    /// File from which to read events.
    #[arg()]
    pub(super) input: PathBuf,

    /// Maximum number of events to buffer
    ///
    /// Sorting events requires storing events in a buffer while we wait to see if there is any
    /// other event that belongs to the same series. If there are many interleaved events, you may
    /// need to increase the size of the buffer to properly sort all events.
    ///
    /// A value of zero means the buffer can grow endlessly.
    #[arg(long, default_value_t = DEFAULT_BUFFER)]
    pub(super) max_buffer: usize,

    /// Write event series to a file rather than to stdout.
    #[arg(short, long)]
    pub(super) out: Option<PathBuf>,

    /// Write events to stdout even if --out is used.
    #[arg(long, default_value = "false")]
    pub(super) print: bool,

    /// Json file writer if any.
    #[arg(skip)]
    file_writer: Option<BufWriter<File>>,
}

impl Sort {
    // Print a series. For now we only support json format which is not very useful.
    // FIXME: It's still unclear how the formatting API will look like. When it is, this should be
    // adapted.
    // For now, print a
    fn print_series(series: &EventSeries) -> Result<()> {
        println!("{}", &series.to_json());
        Ok(())
    }

    fn write_json_series(&mut self, series: &EventSeries) -> Result<()> {
        if let Some(writer) = self.file_writer.as_mut() {
            let bytes = series.to_json().to_string().as_bytes().to_vec();
            writer.write_all(&bytes)?;
            writer.write_all(b"\n")?;
            Ok(())
        } else {
            Ok(())
        }
    }

    fn output(&mut self, series: EventSeries) -> Result<()> {
        self.write_json_series(&series)?;
        if self.file_writer.is_none() || self.print {
            Self::print_series(&series)?;
        }
        Ok(())
    }
}

impl SubCommandParserRunner for Sort {
    fn run(&mut self, modules: Modules) -> Result<()> {
        // Create running instance that will handle signal termination.
        let mut run = Running::new();
        run.register_term_signals()?;

        // Create event factory.
        let mut factory = FileEventsFactory::new(self.input.as_path())?;
        factory.start(modules.section_factories()?)?;

        let mut series = EventSorter::new();
        let mut tracker = AddTracking::new();
        if let Some(out) = &self.out {
            self.file_writer = Some(BufWriter::new(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(out)
                    .or_else(|_| bail!("Could not create or open '{}'", out.display()))?,
            ));
        }

        while run.running() {
            match factory.next_event(None)? {
                EventResult::Event(mut event) => {
                    // Add tracking information
                    tracker.process_one(&mut event)?;

                    // Add to sorter
                    series.add(event);

                    // Flush to stdout the latest series if needed
                    if self.max_buffer != 0 {
                        while series.len() >= self.max_buffer {
                            // Flush the oldest series
                            match series.pop_oldest()? {
                                Some(series) => self.output(series)?,
                                None => break,
                            };
                        }
                    }
                }
                EventResult::Eof => break,
                EventResult::Timeout => continue,
            }
        }
        // Flush remaining events
        while series.len() > 0 {
            match series.pop_oldest()? {
                Some(series) => self.output(series)?,
                None => break,
            };
        }

        // Flush writers
        if let Some(writer) = self.file_writer.as_mut() {
            writer.flush()?;
        }
        Ok(())
    }
}
