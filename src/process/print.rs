//! # Print
//!
//! Print is a simple post-processing command that just parses events and prints them back to
//! stdout

use std::{
    io::{stdout, Write},
    path::PathBuf,
};

use anyhow::{anyhow, Result};
use clap::Parser;
use log::debug;
use signal_hook::low_level::signal_name;

use crate::{
    cli::*,
    core::{
        events::{file::FileEventsFactory, format::TextFormat},
        signals::Running,
    },
    module::Modules,
    output::{FormatAndWrite, Output},
};

use super::{OutputAction, Processor};

#[derive(Parser, Debug, Default)]
#[command(name = "print", about = "Print events to stdout")]
pub(crate) struct Print {
    #[arg(short, long, help = "Read events from file")]
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

        let f = TextFormat::default();
        let writer: Box<dyn Write> = Box::new(stdout());
        let mut factory = FileEventsFactory::new(source)?;

        let mut run = Running::new();
        for sig in signal_hook::consts::TERM_SIGNALS {
            debug!("Registering {}", signal_name(*sig).unwrap());
            run.register_signal(*sig)?;
        }

        let mut p = Processor::new(&mut factory)?;
        let output: Box<dyn Output> = Box::new(FormatAndWrite::new(Box::new(f), vec![writer]));
        p.add_stage(
            "output".to_string(),
            Box::new(OutputAction::from(&mut vec![output])),
        )?;
        p.run(run, modules.section_factories()?)?;
        Ok(())
    }
}
