//! # Sort
//!
//! Sort rearranges the events so they are grouped by skb tracking id (or OVS queue_id if present)

use std::{
    fs::OpenOptions,
    io::{stdout, BufWriter},
    path::PathBuf,
};

use anyhow::{bail, Result};
use clap::Parser;

use crate::{
    cli::*,
    events::{file::FileEventsFactory, *},
    helpers::signals::Running,
    process::{display::*, series::EventSorter, tracking::AddTracking},
};

/// The default size of the sorting buffer
const DEFAULT_BUFFER: usize = 1000;

#[derive(Parser, Debug, Default)]
#[command(
    name = "sort",
    about = "Sort stored events in series based on tracking id.",
    long_about = "Sort stored events in series based on tracking id.

Reads events and arranges them by tracking id. The output is a number of \"event sets\". An event set is a list of events that share the same tracking id (i.e: belong to the same packet)."
)]
pub(crate) struct Sort {
    #[arg(default_value = "retis.data", help = "File from which to read events")]
    pub(super) input: PathBuf,

    #[arg(
        long,
        default_value_t = DEFAULT_BUFFER,
        help = "Maximum number of events to buffer

Sorting events requires storing events in a buffer while we wait to see if there is any other event that belongs to the same series. If there are many interleaved events, you may need to increase the size of the buffer to properly sort all events.

A value of zero means the buffer can grow endlessly."
    )]
    pub(super) max_buffer: usize,

    #[arg(
        short,
        long,
        help = "Write event series to a file rather than to stdout"
    )]
    pub(super) out: Option<PathBuf>,

    #[arg(long, help = "Write events to stdout even if --out is used")]
    pub(super) print: bool,

    #[arg(
        long,
        value_enum,
        default_value_t=CliDisplayFormat::MultiLine,
        help = "Format used when printing an event"
    )]
    pub(super) format: CliDisplayFormat,

    #[arg(long, help = "Print the time as UTC")]
    pub(super) utc: bool,

    #[arg(short = 'e', help = "Print link-layer information from the packet")]
    pub(super) print_ll: bool,
}

impl SubCommandParserRunner for Sort {
    fn run(&mut self, _: &MainConfig) -> Result<()> {
        // Create running instance that will handle signal termination.
        let run = Running::new();
        run.register_term_signals()?;

        // Create event factory.
        let mut factory = FileEventsFactory::new(self.input.as_path())?;

        if matches!(factory.file_type(), file::FileType::Series) {
            log::info!("File already sorted");
            return Ok(());
        }

        let mut series = EventSorter::new();
        let mut tracker = AddTracking::new();
        let mut printers = Vec::new();

        if let Some(out) = &self.out {
            if factory.is_compat() {
                bail!("Storing sorted events is not supported (input event format is too old, remove `--out`)");
            }

            let out = match out.canonicalize() {
                Ok(out) => out,
                // If the file doesn't exist we can't use fs::canonicalize() but it is not needed
                // as that means it is not the input file.
                Err(_) => out.clone(),
            };

            // Make sure we don't use the same file as the result will be the deletion of the
            // original files. If the input file doesn't exist we will raise an error.
            if out.eq(&self.input.canonicalize()?) {
                bail!("Cannot sort a file in-place. Please specify an output file that's different to the input one.");
            }

            printers.push(PrintSeries::new(
                Box::new(BufWriter::new(
                    OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&out)
                        .or_else(|_| bail!("Could not create or open '{}'", out.display()))?,
                )),
                PrintEventFormat::Json,
            ));
        }

        if self.out.is_none() || self.print {
            let format = DisplayFormat::new()
                .multiline(self.format == CliDisplayFormat::MultiLine)
                .time_format(if self.utc {
                    TimeFormat::UtcDate
                } else {
                    TimeFormat::MonotonicTimestamp
                })
                .print_ll(self.print_ll);

            printers.push(PrintSeries::new(
                Box::new(stdout()),
                PrintEventFormat::Text(format),
            ));
        }

        while run.running() {
            match factory.next_event()? {
                Some(mut event) => {
                    // Add tracking information
                    tracker.process_one(&mut event)?;

                    // Add to sorter
                    series.add(event);

                    // Flush to stdout the latest series if needed
                    if self.max_buffer != 0 {
                        while series.len() >= self.max_buffer {
                            // Flush the oldest series
                            match series.pop_oldest()? {
                                Some(series) => printers
                                    .iter_mut()
                                    .try_for_each(|p| p.process_one(&series))?,
                                None => break,
                            };
                        }
                    }
                }
                None => break,
            }
        }
        // Flush remaining events
        while series.len() > 0 {
            match series.pop_oldest()? {
                Some(series) => printers
                    .iter_mut()
                    .try_for_each(|p| p.process_one(&series))?,
                None => break,
            };
        }

        // Flush writers
        printers.iter_mut().try_for_each(|p| p.flush())?;
        Ok(())
    }
}
