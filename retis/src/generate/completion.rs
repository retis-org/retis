//! # Completion
//!
//! Generate a completions file for a specified shell at runtime.

use std::{any::Any, io::Write, path::PathBuf};

use anyhow::Result;
use clap::{
    error::Error as ClapError,
    {value_parser, ArgMatches, Command, Parser},
};
use clap_complete::{generate, Generator, Shell};

use crate::cli::*;

/// Generate completion file for a specified shell
#[derive(Parser, Debug, Default)]
#[command(name = "sh-complete")]
pub(crate) struct Complete {
    /// Specify shell to complete for
    // We use an Option and require the parameter to be set here to allow
    // deriving Default on Complete.
    #[arg(long, required = true, value_parser(value_parser!(Shell)))]
    shell: Option<Shell>,

    /// Path to write completion-registration to
    #[arg(long)]
    register: Option<PathBuf>,
}

impl SubCommand for Complete {
    fn new() -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self::default())
    }

    fn name(&self) -> String {
        <Self as clap::CommandFactory>::command()
            .get_name()
            .to_string()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn command(&mut self) -> Result<Command> {
        Ok(<Self as clap::CommandFactory>::command())
    }

    fn update_from_arg_matches(&mut self, args: &ArgMatches) -> Result<(), ClapError> {
        <Self as clap::FromArgMatches>::update_from_arg_matches(self, args)
    }

    fn runner(&self) -> Result<Box<dyn SubCommandRunner>> {
        Ok(Box::new(CompleteRunner {}))
    }
}

#[derive(Debug)]
pub(crate) struct CompleteRunner {}

impl SubCommandRunner for CompleteRunner {
    fn run(&mut self, cli: CliConfig) -> Result<()> {
        let mut cmd = cli.command.clone();
        let matches = cli.command.clone().get_matches();

        if let Some(sub_m) = matches.subcommand_matches("sh-complete") {
            if let Some(generator) = sub_m.get_one::<Shell>("shell") {
                let mut buf = Vec::new();
                let name = cmd.get_name().to_string();

                generate(*generator, &mut cmd, name.clone(), &mut buf);
                if let Some(out_path) = sub_m.get_one::<PathBuf>("register") {
                    if out_path.is_dir() {
                        let out_path = out_path.join(generator.file_name(&name));
                        let _ = std::fs::write(out_path, buf);
                    } else {
                        let _ = std::fs::write(out_path, buf);
                    }
                } else {
                    let _ = std::io::stdout().write_all(&buf);
                }
            }
        }
        Ok(())
    }
}
