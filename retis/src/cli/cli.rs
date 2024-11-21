//! # Cli
//!
//! Cli module, providing tools for registering and accessing command line interface arguments
//! as well as defining the subcommands that the tool supports.
#![allow(dead_code)] // FIXME
use std::{any::Any, convert::From, env, ffi::OsString, fmt::Debug, path::PathBuf};

use anyhow::{anyhow, bail, Result};
use clap::{
    builder::PossibleValuesParser,
    error::Error as ClapError,
    error::ErrorKind,
    {ArgMatches, Args, Command, FromArgMatches, ValueEnum},
};
use log::debug;

use super::dynamic::DynamicCommand;
#[cfg(feature = "benchmark")]
use crate::benchmark::cli::Benchmark;
use crate::{
    collect::cli::Collect,
    collect::collector::Modules,
    events::SectionId,
    generate::Complete,
    inspect::Inspect,
    process::cli::*,
    profiles::{cli::ProfileCmd, Profile},
};

/// SubCommandRunner defines the common interface to run SubCommands.
pub(crate) trait SubCommandRunner {
    /// Run the subcommand with a given set of modules and cli configuration
    fn run(&mut self, cli: FullCli, modules: Modules) -> Result<()>;
}

/// SubCommandRunnerFunc is a wrapper for functions that implements SubCommandRunner
pub(crate) struct SubCommandRunnerFunc<F>
where
    F: Fn(FullCli, Modules) -> Result<()>,
{
    func: F,
}

impl<F> SubCommandRunnerFunc<F>
where
    F: Fn(FullCli, Modules) -> Result<()>,
{
    pub(crate) fn new(func: F) -> Self {
        Self { func }
    }
}

impl<F> SubCommandRunner for SubCommandRunnerFunc<F>
where
    F: Fn(FullCli, Modules) -> Result<()>,
{
    fn run(&mut self, cli: FullCli, modules: Modules) -> Result<()> {
        (self.func)(cli, modules)
    }
}

/// SubCommand defines the way to handle SubCommands.
/// SubCommands arguments are parsed in two rounds, the "thin" and the "full" round.
///
/// In the "thin" round a SubCommand should only define a simple clap Command with a short help
/// string (about in clap's parlace). This will be used to show the main program's help.
///
/// When the Cli parses the command line arguments on the first round and determines which
/// subcommand was called, there is a moment where modules can dynamically register command line
/// arguments with the apropriate SubCommand. After, the Cli will run the "full" parsing during
/// which argument validation will be performend.
pub(crate) trait SubCommand {
    /// Allocate and return a new instance of a SubCommand.
    fn new() -> Result<Self>
    where
        Self: Sized;

    /// Returns the unique name of the subcommand.
    fn name(&self) -> String;

    /// Returns self as a std::any::Any trait.
    ///
    /// This is useful for dynamically downcast the SubCommand into it's specific type to access
    /// subcommand-specific functionality.
    fn as_any(&self) -> &dyn Any;

    /// Returns self as a mutable std::any::Any trait.
    ///
    /// This is useful for dynamically downcast the SubCommand into it's specific type to access
    /// subcommand-specific functionality.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Generate the clap Command to be used for "full" parsing.
    ///
    /// This method should be called after all dynamic options have been registered.
    fn full(&mut self) -> Result<Command>;

    /// Updates internal structures with clap's ArgMatches.
    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), ClapError>;

    /// Return the DynamicCommand handler.
    ///
    /// Useful for module arguments retrieval.
    fn dynamic(&self) -> Option<&DynamicCommand> {
        None
    }

    /// Return a mutable reference to the DynamicCommand handler.
    ///
    /// Useful for module registration.
    fn dynamic_mut(&mut self) -> Option<&mut DynamicCommand> {
        None
    }

    /// Return a SubCommandRunner capable of running this command.
    fn runner(&self) -> Result<Box<dyn SubCommandRunner>>;
}

impl Debug for dyn SubCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SubCommand ({})", self.name())
    }
}

/// Trait to convert a clap::Parser into a SubCommandRunner.
pub(crate) trait SubCommandParserRunner: clap::Parser + Default {
    fn run(&mut self, modules: Modules) -> Result<()>;
}

// Default implementation of SubCommand for all SubCommandParserRunner.
// This makes it much easier to implement small and easy subcommands without much boilerplate.
impl<F> SubCommand for F
where
    F: SubCommandParserRunner + 'static,
{
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

    fn full(&mut self) -> Result<Command> {
        Ok(<Self as clap::CommandFactory>::command())
    }

    fn update_from_arg_matches(&mut self, args: &ArgMatches) -> Result<(), ClapError> {
        <Self as clap::FromArgMatches>::update_from_arg_matches(self, args)
    }

    fn runner(&self) -> Result<Box<dyn SubCommandRunner>> {
        Ok(Box::new(SubCommandRunnerFunc::new(
            |cli: FullCli, modules: Modules| -> Result<()> {
                let mut cli = cli.run()?;
                let cmd: &mut Self = cli
                    .subcommand
                    .as_any_mut()
                    .downcast_mut::<Self>()
                    .ok_or_else(|| anyhow!("wrong subcommand"))?;
                cmd.run(modules)
            },
        )))
    }
}

/// Trace packets on the Linux kernel
///
/// retis is a tool for capturing networking-related events from the system using ebpf and analyzing them.
#[derive(Args, Debug, Default)]
pub(crate) struct MainConfig {
    #[arg(
        long,
        value_parser=PossibleValuesParser::new(["error", "warn", "info", "debug", "trace"]),
        default_value = "info",
        help = "Log level",
    )]
    pub(crate) log_level: String,
    #[arg(
        long,
        short,
        value_delimiter = ',',
        help = "Comma separated list of profile names to apply"
    )]
    pub(crate) profile: Vec<String>,
    #[arg(
        long,
        help = "Path to kernel configuration (e.g. /boot/config-6.3.8-200.fc38.x86_64; default: auto-detect)"
    )]
    pub(crate) kconf: Option<PathBuf>,
}

/// ThinCli handles the first (a.k.a "thin") round of Command Line Interface parsing.
///
/// During this phase, SubCommands can be added. After all SubCommands have been added, the build()
/// method will run the thin CLI parsing that does not perform dynamic subcommand argument
/// validation and yield a FullCli object to represent the results.
#[derive(Debug)]
pub(crate) struct ThinCli {
    subcommands: Vec<Box<dyn SubCommand>>,
}

impl ThinCli {
    /// Allocate and return a new ThinCli object that will parse the command arguments.
    pub(crate) fn new() -> Result<Self> {
        Ok(ThinCli {
            subcommands: Vec::new(),
        })
    }

    /// Add a subcommand to the ThinCli object.
    pub(crate) fn add_subcommand(&mut self, sub: Box<dyn SubCommand>) -> Result<&mut Self> {
        let name = sub.name();

        if self.subcommands.iter().any(|s| s.name() == name) {
            bail!("Subcommand already registered")
        }

        self.subcommands.push(sub);
        Ok(self)
    }

    /// Build a FullCli by running a first round of CLI parsing without subcommand argument
    /// validation.
    /// If clap reports an error (including "--help" and "--version"), print the message and
    /// exit the program.
    pub(crate) fn build(self) -> FullCli {
        self.build_from(env::args_os()).unwrap_or_else(|e| e.exit())
    }

    /// Build a FullCli by running a first round of CLI parsing with the given list of arguments.
    /// This function should be only used directly by unit tests.
    pub(crate) fn build_from<I, T>(mut self, args: I) -> Result<FullCli, ClapError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let pkg_version = option_env!("RELEASE_VERSION").unwrap_or("unspec");
        let pkg_name = option_env!("RELEASE_NAME").unwrap_or("unreleased");

        let version = if cfg!(debug_assertions) {
            format!("{} [dbg] (\"{}\")", pkg_version, pkg_name)
        } else {
            format!("{} (\"{}\")", pkg_version, pkg_name)
        };

        let args: Vec<OsString> = args.into_iter().map(|x| x.into()).collect();
        let mut command = MainConfig::augment_args(Command::new("retis"))
            .version(version)
            .disable_help_subcommand(true)
            .infer_subcommands(true)
            .subcommand_required(true);
        // Add full subcommands so that the main help shows them.
        for sub in self.subcommands.iter_mut() {
            command = command.subcommand(sub.full().expect("full command failed"));
        }

        // Determine the subcommand that was run while ignoring errors from yet-to-be-defined
        // arguments.
        let matches = command
            .clone()
            .ignore_errors(true)
            .try_get_matches_from(args.iter())?;

        let ran_subcommand = matches
            .subcommand_name()
            .and_then(|name| self.subcommands.drain(..).find(|s| s.name() == name))
            .ok_or_else(||
                // There is no subcommand or it's invalid. Re-run the match to generate
                // the right clap error that to be printed nicely.
                command
                    .try_get_matches_from_mut(args.iter())
                    .expect_err("clap should fail with no arguments"))?;

        // Get main config.
        let mut main_config = MainConfig::default();
        main_config.update_from_arg_matches(&matches)?;

        // A command was run, build the FullCli so we can parse it.
        Ok(FullCli {
            args,
            main_config,
            command,
            subcommand: ran_subcommand,
        })
    }
}

/// FullCli handles the second (a.k.a "full") round of Command Line Interface parsing.
///
/// When a FullCli is created it can be used to dynamically add command line arguments to the
/// SubCommand that was ran. After this phase, a call to run() will perform the full argument
/// validation.
#[derive(Debug)]
pub(crate) struct FullCli {
    pub(crate) main_config: MainConfig,
    args: Vec<OsString>,
    command: Command,
    subcommand: Box<dyn SubCommand>,
}

impl FullCli {
    /// Enhance arguments with provided profile.
    fn enhance_profile(&mut self) -> Result<()> {
        if self.main_config.profile.is_empty() {
            return Ok(());
        }

        for name in self.main_config.profile.iter() {
            let profile = Profile::find(name.as_str())?;
            let mut extra_args = profile.cli_args(self.subcommand.name().as_str())?;
            self.args.append(&mut extra_args);
        }
        Ok(())
    }
    /// Perform full CLI parsing and validation
    pub(crate) fn run(mut self) -> Result<CliConfig, ClapError> {
        self.enhance_profile().map_err(|err| {
            self.command
                .error(ErrorKind::InvalidValue, format!("{err}"))
        })?;

        debug!(
            "Resulting CLI arguments: {}",
            self.args
                .iter()
                .map(|o| o.as_os_str().to_str().unwrap_or("<encoding error>"))
                .collect::<Vec<&str>>()
                .join(" ")
        );

        // Get the matches.
        let matches = match cfg!(test) {
            true => self.command.try_get_matches_from_mut(self.args.iter())?,
            false => self
                .command
                .try_get_matches_from_mut(self.args.iter())
                .unwrap_or_else(|e| e.exit()),
        };

        let (subcommand, matches) = matches
            .subcommand()
            .expect("full parsing did not find subcommand");
        if !subcommand.to_string().eq(&self.subcommand.as_ref().name()) {
            // thin and full cli parsing should yield the same subcommand. There is no way to
            // recover from this error, so let's just panic.
            panic!("Thin and full parsing did not yield the same subcommand");
        }

        // Update subcommand options.
        match cfg!(test) {
            true => self.subcommand.update_from_arg_matches(matches)?,
            false => self
                .subcommand
                .update_from_arg_matches(matches)
                .unwrap_or_else(|e| e.exit()),
        }
        Ok(CliConfig {
            main_config: self.main_config,
            subcommand: self.subcommand,
        })
    }

    pub(crate) fn get_subcommand(&self) -> Result<&dyn SubCommand> {
        Ok(self.subcommand.as_ref())
    }

    pub(crate) fn get_subcommand_mut(&mut self) -> Result<&mut dyn SubCommand> {
        Ok(self.subcommand.as_mut())
    }

    pub(crate) fn get_command(&self) -> Command {
        self.command.clone()
    }
}

/// CliConfig represents the result of the Full CLI parsing
#[derive(Debug)]
pub(crate) struct CliConfig {
    pub(crate) main_config: MainConfig,
    pub(crate) subcommand: Box<dyn SubCommand>,
}

impl CliConfig {
    /// Creates and returns a new instance of dynamic module argument type M
    pub(crate) fn get_section<M>(&self, id: SectionId) -> Result<M>
    where
        M: Default + FromArgMatches,
    {
        self.subcommand
            .dynamic()
            .ok_or_else(|| {
                anyhow!(format!(
                    "subcommand {} does not support dynamic arguments",
                    self.subcommand.name()
                ))
            })?
            .get_section::<M>(id)
    }
}

/// Type of the "format" argument.
// It is an enum that maps 1:1 with the formats defined in events library.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub(crate) enum CliDisplayFormat {
    SingleLine,
    #[default]
    MultiLine,
}

/// Create and register a ThinCli
pub(crate) fn get_cli() -> Result<ThinCli> {
    let mut cli = ThinCli::new()?;
    cli.add_subcommand(Box::new(Collect::new()?))?;
    cli.add_subcommand(Box::new(Print::new()?))?;
    cli.add_subcommand(Box::new(Sort::new()?))?;
    #[cfg(feature = "python")]
    cli.add_subcommand(Box::new(PythonCli::new()?))?;
    cli.add_subcommand(Box::new(Pcap::new()?))?;
    cli.add_subcommand(Box::new(Inspect::new()?))?;
    cli.add_subcommand(Box::new(ProfileCmd::new()?))?;
    cli.add_subcommand(Box::new(Complete::new()?))?;

    #[cfg(feature = "benchmark")]
    cli.add_subcommand(Box::new(Benchmark::new()?))?;

    Ok(cli)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[derive(Debug, Default, Args)]
    struct Sub1 {
        #[arg(id = "sub1-arg", long)]
        someopt: Option<String>,
    }

    impl SubCommand for Sub1 {
        fn new() -> Result<Self> {
            Ok(Sub1 { someopt: None })
        }
        fn name(&self) -> String {
            "sub1".to_string()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
        fn full(&mut self) -> Result<Command> {
            Ok(Sub1::augment_args(
                Command::new("sub1")
                    .about("does some things")
                    .long_about("this is a longer description"),
            ))
        }
        fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), ClapError> {
            <Self as FromArgMatches>::update_from_arg_matches(self, matches)
        }
        fn runner(&self) -> Result<Box<dyn SubCommandRunner>> {
            Ok(Box::new(SubCommandRunnerFunc::new(
                |_: FullCli, _: Modules| Ok(()),
            )))
        }
    }

    #[derive(Debug, Default, clap::Parser)]
    #[command(name = "sub2", about = "sub2 help")]
    struct Sub2 {
        #[arg(id = "sub2-flag", long)]
        flag: Option<bool>,
    }

    impl SubCommandParserRunner for Sub2 {
        fn run(&mut self, _: Modules) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn cli_register_subcommands() -> Result<()> {
        let mut cli = ThinCli::new()?;
        assert!(cli.add_subcommand(Box::new(Sub1::new()?)).is_ok());
        assert!(cli.add_subcommand(Box::<Sub2>::default()).is_ok());
        assert!(cli.add_subcommand(Box::new(Sub1::new()?)).is_err());
        Ok(())
    }

    #[test]
    fn cli_build() -> Result<()> {
        let mut cli = ThinCli::new()?;
        assert!(cli.add_subcommand(Box::new(Sub1::new()?)).is_ok());
        assert!(cli.add_subcommand(Box::<Sub2>::default()).is_ok());

        let err = cli.build_from(vec!["retis", "--help"]);
        assert!(err.is_err() && err.unwrap_err().kind() == ErrorKind::DisplayHelp);

        Ok(())
    }

    #[test]
    fn cli_full_help() -> Result<()> {
        let mut cli = ThinCli::new()?;
        assert!(cli.add_subcommand(Box::new(Sub1::new()?)).is_ok());
        assert!(cli.add_subcommand(Box::<Sub2>::default()).is_ok());

        let cli = cli.build_from(vec!["retis", "sub1", "--help"]);
        assert!(cli.is_ok());

        let err = cli?.run();
        assert!(err.is_err() && err.unwrap_err().kind() == ErrorKind::DisplayHelp);

        Ok(())
    }

    #[test]
    fn cli_sub_args() -> Result<()> {
        let mut cli = ThinCli::new()?;
        assert!(cli.add_subcommand(Box::new(Sub1::new()?)).is_ok());
        assert!(cli.add_subcommand(Box::<Sub2>::default()).is_ok());

        let cli = cli.build_from(vec!["retis", "sub1", "--sub1-arg", "foo"]);
        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert!(cli.get_subcommand().is_ok() && cli.get_subcommand().unwrap().name().eq("sub1"));

        let res = cli.run();
        assert!(res.is_ok());
        let res = res.unwrap();
        assert!(res.subcommand.name().eq("sub1"));
        let sub1 = res.subcommand.as_any().downcast_ref::<Sub1>();
        assert!(sub1.is_some());
        assert!(sub1.unwrap().someopt.as_ref().unwrap().eq("foo"));

        Ok(())
    }

    #[test]
    fn cli_sub_args_err() -> Result<()> {
        let mut cli = ThinCli::new()?;
        assert!(cli.add_subcommand(Box::new(Sub1::new()?)).is_ok());
        assert!(cli.add_subcommand(Box::<Sub2>::default()).is_ok());

        let cli = cli.build_from(vec!["retis", "sub1", "--noexists", "foo"]);
        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert!(cli.get_subcommand().is_ok() && cli.get_subcommand().unwrap().name().eq("sub1"));

        let res = cli.run();
        assert!(res.is_err() && res.unwrap_err().kind() == ErrorKind::UnknownArgument);

        Ok(())
    }
}
