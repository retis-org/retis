//! # Collect
//!
//! Collect is a dynamic CLI subcommand that allows collectors to register their arguments.

use anyhow::Result;
use std::any::Any;

use clap::error::Error as ClapError;
use clap::{builder::PossibleValuesParser, error::ErrorKind, Arg, ArgMatches, Args, Command};

use crate::cli::{dynamic::DynamicCommand, SubCommand};

#[derive(Args, Debug, Default)]
pub(crate) struct CollectArgs {
    #[arg(long, default_value = "false")]
    pub(super) ebpf_debug: Option<bool>,
    // Some of the options that we want for this arg are not available in clap's derive interface
    // so both the argument definition and the field population will be done manually.
    #[arg(skip)]
    pub(super) collectors: Vec<String>,
    // Use the plural in the struct but singular for the cli parameter as we're
    // dealing with a list here.
    #[arg(
        id = "probe",
        short,
        long,
        help = "Add a probe on the given target. Can be used multiple times. Probes should
follow the TYPE:TARGET pattern.

Valid TYPEs:
- kprobe: kernel probes.
- tp: kernel tracepoints.

Example: --probe tp:skb:kfree_skb --probe kprobe:consume_skb"
    )]
    pub(super) probes: Vec<String>,
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
                CollectArgs::augment_args(Command::new("collect")).arg(
                    Arg::new("collectors")
                        .long("collectors")
                        .short('c')
                        .value_delimiter(',')
                        .help("comma-separated list of collectors to enable"),
                ),
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

        // Determine all registerd collectors and specify both the possible values and the default
        // value of the "collectors" argument
        let possible_collectors =
            Vec::from_iter(self.collectors.modules().iter().map(|x| x.to_owned()));

        let full_command = self
            .collectors
            .command()
            .to_owned()
            .about("Collect events")
            .long_about(long_about)
            .mut_arg("collectors", |a| {
                a.value_parser(PossibleValuesParser::new(possible_collectors.clone()))
                    .default_value(possible_collectors.join(","))
            });

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

        // Manually set collectors argument.
        self.args.collectors = args
            .get_many("collectors")
            .ok_or_else(|| ClapError::new(ErrorKind::MissingRequiredArgument))?
            .map(|x: &String| x.to_owned())
            .collect();
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
