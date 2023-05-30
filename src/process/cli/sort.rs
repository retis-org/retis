//! # Sort
//!
//! Sort rearranges the events so they are grouped by skb tracking id (or OVS queue_id if present)

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::Parser;
use log::debug;

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
}

impl Sort {
    // Print a series. For now we only support json format which is not very useful.
    // FIXME: It's still unclear how the formatting API will look like. When it is, this should be
    // adapted.
    // For now, print a
    fn print_series(series: EventSeries) -> Result<()> {
        //println!("{}", serde_json::to_string_pretty(&series.to_json())?);
        use crate::core::events::EventDisplay;
        if series.events.len() >= 1 {
            println!("* {}\n", series.events.get(0).unwrap().display());
            for e in series.events.iter().skip(0) {
                println!("    \\_ {}\n", e.display());
            }
        }
        Ok(())
    }
}

impl SubCommandRunner for Sort {
    fn run(&mut self, cli: FullCli, modules: Modules) -> Result<()> {
        let cli = cli.run()?;
        let sort = &cli
            .subcommand
            .as_any()
            .downcast_ref::<Sort>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?;

        // Create running instance that will handle signal termination.
        let mut run = Running::new();
        run.register_term_signals()?;

        // Create event factory.
        let mut factory = FileEventsFactory::new(sort.input.as_path())?;
        factory.start(modules.section_factories()?)?;

        let mut series = EventSorter::new();
        let mut tracker = AddTracking::new();

        use EventResult::*;
        while run.running() {
            match factory.next_event(None)? {
                Event(mut event) => {
                    // Add tracking information
                    if let Err(err) = tracker.process_one(&mut event) {
                        debug!("Failed to add tracking information to event: {err}");
                    }

                    // Add to sorter
                    series.add(event);

                    // Flush to stdout the latest series if needed
                    if sort.max_buffer != 0 {
                        while series.len() >= sort.max_buffer {
                            // Flush the oldest series
                            match series.pop_oldest()? {
                                Some(series) => Self::print_series(series)?,
                                None => break,
                            };
                        }
                    }
                }
                Eof => break,
                Timeout => continue,
            }
        }
        // Flush remaining events
        while series.len() > 0 {
            match series.pop_oldest()? {
                Some(series) => Self::print_series(series)?,
                None => break,
            };
        }
        Ok(())
    }
}
