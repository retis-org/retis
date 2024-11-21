use std::path::PathBuf;

use anyhow::Result;
use clap::{arg, Parser};

use crate::{cli::*, collect::collector::Modules, events::python_embed::shell_execute};

/// Runs Python scripts with events imported.
#[derive(Parser, Debug, Default)]
#[command(name = "python")]
pub(crate) struct PythonCli {
    #[arg(
        long,
        short,
        default_value = "retis.data",
        help = "File from which to read events"
    )]
    pub(super) input: PathBuf,
    #[arg(help = "Python script to execute. Omit to drop into an interactive shell.")]
    pub(super) script: Option<PathBuf>,
}

impl SubCommandParserRunner for PythonCli {
    fn run(&mut self, _modules: Modules) -> Result<()> {
        shell_execute(self.input.clone(), self.script.as_ref())
    }
}
