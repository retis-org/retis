//! # Print
//!
//! Print is a simple post-processing command that just parses events and prints them back to
//! stdout

use std::io::{self, stdout, ErrorKind};

use anyhow::Result;
use clap::Parser;

use crate::{
    cli::*,
    events::{file::*, *},
    helpers::{file_rotate::InputDataFile, signals::Running},
    process::display::*,
};

#[derive(Parser, Debug, Default)]
#[command(name = "print", about = "Print stored events to stdout.")]
pub(crate) struct Print {
    #[arg(help = InputDataFile::help())]
    pub(super) input: Option<InputDataFile>,
    #[arg(long, help = "Format used when printing an event")]
    #[clap(value_enum, default_value_t=CliDisplayFormat::MultiLine)]
    pub(super) format: CliDisplayFormat,
    #[arg(long, help = "Print the time as UTC")]
    pub(super) utc: bool,
    #[arg(short = 'e', help = "Print link-layer information from the packet")]
    pub(super) print_ll: bool,
}

impl SubCommandParserRunner for Print {
    fn run(&mut self, _: &MainConfig) -> Result<()> {
        // Create running instance that will handle signal termination.
        let run = Running::new();
        run.register_term_signals()?;

        // Create event factory.
        let mut factory = self.input.clone().unwrap_or_default().to_factory()?;

        // Format.
        let format = DisplayFormat::new()
            .multiline(self.format == CliDisplayFormat::MultiLine)
            .time_format(if self.utc {
                TimeFormat::UtcDate
            } else {
                TimeFormat::MonotonicTimestamp
            })
            .print_ll(self.print_ll);

        match factory.file_type() {
            FileType::Event => {
                // Formatter & printer for events.
                let mut event_output =
                    PrintEvent::new(Box::new(stdout()), PrintEventFormat::Text(format));

                while run.running() {
                    match factory.next_event()? {
                        Some(event) => {
                            if let Err(e) = event_output.process_one(&event) {
                                match e.downcast_ref::<io::Error>() {
                                    Some(io_error) if io_error.kind() == ErrorKind::BrokenPipe => {
                                        break
                                    }
                                    _ => return Err(e),
                                }
                            }
                        }
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
                        Some(series) => {
                            if let Err(e) = series_output.process_one(&series) {
                                match e.downcast_ref::<io::Error>() {
                                    Some(io_error) if io_error.kind() == ErrorKind::BrokenPipe => {
                                        break
                                    }
                                    _ => return Err(e),
                                }
                            }
                        }
                        None => break,
                    }
                }
            }
        }

        Ok(())
    }
}
