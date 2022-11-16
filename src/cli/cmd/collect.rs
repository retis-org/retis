//! # Collect
//!
//! Collect is a dynamic CLI subcommand that allows collectors to register their arguments.

use anyhow::Result;
use std::any::Any;

use clap::error::Error as ClapError;
use clap::{error::ErrorKind, ArgMatches, Args, Command};

use super::super::dynamic::DynamicCommand;
use super::super::SubCommand;

#[derive(Args, Debug, Default)]
pub(crate) struct CollectArgs {
    #[arg(long, default_value = "false")]
    pub(crate) ebpf_debug: Option<bool>,
}

#[derive(Debug)]
pub(crate) struct Collect {
    args: CollectArgs,
    collectors: DynamicCommand,
}

impl SubCommand for Collect {
    fn new() -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Collect {
            args: CollectArgs::default(),
            collectors: DynamicCommand::new(
                CollectArgs::augment_args(Command::new("collect")),
                "collector",
            )?,
        })
    }

    fn thin(&self) -> Result<Command> {
        Ok(Command::new("collect").about("Collect network events"))
    }

    fn name(&self) -> &'static str {
        "collect"
    }

    fn dynamic(&self) -> Option<&DynamicCommand> {
        Some(&self.collectors)
    }

    fn dynamic_mut(&mut self) -> Option<&mut DynamicCommand> {
        Some(&mut self.collectors)
    }

    fn full(&self) -> Result<Command> {
        let long_about = "Collect events using 'collectors'.\n\n \
            Collectors are modules that extract \
            events from different places of the kernel or userspace daemons \
            using ebpf."
            .to_string();

        let full_command = self
            .collectors
            .command()
            .to_owned()
            .about("Collect events")
            .long_about(long_about);

        Ok(full_command)
    }

    fn update_from_arg_matches(&mut self, args: &ArgMatches) -> Result<(), ClapError> {
        self.collectors
            .set_matches(args)
            .map_err(|_| ClapError::new(ErrorKind::InvalidValue))?;
        self.args = self
            .collectors
            .get_main::<CollectArgs>()
            .map_err(|_| ClapError::new(ErrorKind::InvalidValue))?;
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Collect {
    /// Returns the main Collect arguments
    pub(crate) fn args(&self) -> Result<&CollectArgs> {
        Ok(&self.args)
    }
}
