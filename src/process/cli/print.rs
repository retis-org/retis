//! # Print
//!
//! Print is a simple post-processing command that just parses events and prints them back to
//! stdout

use std::{
    io::{stdout, Write},
    path::PathBuf,
    time::Duration,
};

use anyhow::{anyhow, Result};
use clap::Parser;

use crate::{
    cli::*,
    core::{
        events::{
            file::FileEventsFactory,
            format::{FormatAndWrite, JsonFormat},
            EventFactory, EventResult,
        },
        signals::Running,
    },
    module::Modules,
};

/// Print events to stdout
#[derive(Parser, Debug, Default)]
#[command(name = "print")]
pub(crate) struct Print {
    /// File from which to read events.
    #[arg()]
    pub(super) input: PathBuf,
}

impl SubCommandRunner for Print {
    fn run(&mut self, cli: FullCli, modules: Modules) -> Result<()> {
        let cli = cli.run()?;
        let source = &cli
            .subcommand
            .as_any()
            .downcast_ref::<Print>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?
            .input;

        // Create running instance that will handle signal termination.
        let mut run = Running::new();
        run.register_term_signals()?;

        // Create output formatter.
        // For now, we only support printing events back in json format.
        let mut json = JsonFormat::default();
        let writer: Box<dyn Write> = Box::new(stdout());
        let mut output = FormatAndWrite::new(&mut json, vec![writer]);

        // Create event factory.
        let mut factory = FileEventsFactory::new(source)?;
        factory.start(modules.section_factories()?)?;

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
