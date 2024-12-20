//! # Print
//!
//! Print is a simple post-processing command that just parses events and prints them back to
//! stdout

use std::{io::stdout, path::PathBuf};

use anyhow::Result;
use clap::Parser;

use crate::{
    cli::*,
    events::{
        file::{FileEventsFactory, FileType},
        *,
    },
    helpers::signals::Running,
    process::display::*,
};

/// Print stored events to stdout
#[derive(Parser, Debug, Default)]
#[command(name = "print")]
pub(crate) struct Print {
    /// File from which to read events.
    #[arg(default_value = "retis.data")]
    pub(super) input: PathBuf,
    #[arg(long, help = "Format used when printing an event.")]
    #[clap(value_enum, default_value_t=CliDisplayFormat::MultiLine)]
    pub(super) format: CliDisplayFormat,
    #[arg(long, help = "Print the time as UTC")]
    pub(super) utc: bool,
}

impl SubCommandParserRunner for Print {
    fn run(&mut self) -> Result<()> {
        // Create running instance that will handle signal termination.
        let run = Running::new();
        run.register_term_signals()?;

        // Create event factory.
        let mut factory = FileEventsFactory::new(self.input.as_path())?;

        // Format.
        let format = DisplayFormat::new()
            .multiline(self.format == CliDisplayFormat::MultiLine)
            .time_format(if self.utc {
                TimeFormat::UtcDate
            } else {
                TimeFormat::MonotonicTimestamp
            });

        match factory.file_type() {
            FileType::Event => {
                // Formatter & printer for events.
                let mut event_output =
                    PrintEvent::new(Box::new(stdout()), PrintEventFormat::Text(format));

                while run.running() {
                    match factory.next_event()? {
                        Some(event) => event_output.process_one(&event)?,
                        None => break,
                    }
                }
            }
            FileType::Series => {
                // Formatter & printer for series.
                let mut series_output =
                    PrintSeries::new(Box::new(stdout()), PrintEventFormat::Text(format));

                while run.running() {
                    match factory.next_series()? {
                        Some(series) => series_output.process_one(&series)?,
                        None => break,
                    }
                }
            }
        }

        Ok(())
    }
}
