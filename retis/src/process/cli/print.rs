//! # Print
//!
//! Print is a simple post-processing command that just parses events and prints them back to
//! stdout

use std::{io::stdout, path::PathBuf, time::Duration};

use anyhow::Result;
use clap::Parser;

use crate::{
    cli::*,
    events::{file::FileEventsFactory, *},
    helpers::signals::Running,
    module::Modules,
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
    #[clap(value_enum, default_value_t=CliDisplayFormatFlavor::MultiLine)]
    pub(super) format: CliDisplayFormatFlavor,
    #[arg(long, help = "Time format used when printing an event.")]
    #[clap(value_enum, default_value_t=CliTimeFormat::MonotonicTimestamp)]
    pub(super) time_format: CliTimeFormat,
}

impl SubCommandParserRunner for Print {
    fn run(&mut self, _: Modules) -> Result<()> {
        // Create running instance that will handle signal termination.
        let run = Running::new();
        run.register_term_signals()?;

        // Create event factory.
        let mut factory = FileEventsFactory::new(self.input.as_path())?;

        // Format.
        let mut format = DisplayFormat::new(self.format.into());
        format.set_time_format(self.time_format.into());

        // Formatter & printer for events.
        let mut output = PrintSingle::new(Box::new(stdout()), PrintSingleFormat::Text(format));

        use EventResult::*;
        while run.running() {
            match factory.next_event(Some(Duration::from_secs(1)))? {
                Event(event) => output.process_one(&event)?,
                Eof => break,
                Timeout => continue,
            }
        }
        Ok(())
    }
}
