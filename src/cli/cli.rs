//! # Cli
//!
//! Cli module, providing tools for registering and accessing command line interface arguments
//! as well as defining the subcommands that the tool supports.
#![allow(dead_code)] // FIXME
use std::{any::Any, collections::HashMap, env, ffi::OsString, fmt::Debug};

use anyhow::{anyhow, bail, Result};
use clap::{
    builder::PossibleValuesParser,
    error::Error as ClapError,
    {ArgMatches, Args, Command, FromArgMatches},
};

use super::dynamic::DynamicCommand;
use crate::{collect::cli::Collect, module::ModuleId};

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
    fn name(&self) -> &'static str;

    /// Returns self as a std::any::Any trait.
    ///
    /// This is useful for dynamically downcast the SubCommand into it's specific type to access
    /// subcommand-specific functionality.
    fn as_any(&self) -> &dyn Any;

    /// Generate the clap Command to be used for "thin" parsing.
    fn thin(&self) -> Result<Command>;

    /// Generate the clap Command to be used for "full" parsing.
    ///
    /// This method should be called after all dynamic options have been registered.
    fn full(&self) -> Result<Command>;

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
}

impl Debug for dyn SubCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SubCommand ({})", self.name())
    }
}

/// Trace packets on the Linux kernel
///
/// retis is a tool for capturing networking-related events from the system using ebpf and analyzing them.
#[derive(Args, Debug, Default)]
pub(crate) struct MainConfig {
    #[arg(
        long,
        value_parser=PossibleValuesParser::new(["error", "warn", "info", "debug"]),
        default_value = "info",
        help = "Log level",
    )]
    pub(crate) log_level: String,
}

/// ThinCli handles the first (a.k.a "thin") round of Command Line Interface parsing.
///
/// During this phase, SubCommands can be added. After all SubCommands have been added, the build()
/// method will run the thin CLI parsing that does not perform dynamic subcommand argument
/// validation and yield a FullCli object to represent the results.
#[derive(Debug)]
pub(crate) struct ThinCli {
    subcommands: HashMap<String, Box<dyn SubCommand>>,
}

impl ThinCli {
    /// Allocate and return a new ThinCli object that will parse the command arguments.
    pub(crate) fn new() -> Result<Self> {
        Ok(ThinCli {
            subcommands: HashMap::new(),
        })
    }

    /// Add a subcommand to the ThinCli object.
    pub(crate) fn add_subcommand(&mut self, sub: Box<dyn SubCommand>) -> Result<&mut Self> {
        let name = sub.name().to_string();
        if self.subcommands.get(&name).is_some() {
            bail!("Subcommand already registered")
        }
        self.subcommands.insert(name, sub);
        Ok(self)
    }

    /// Build a FullCli by running a first round of CLI parsing without subcommand argument
    /// validation.
    pub(crate) fn build(self) -> Result<FullCli, ClapError> {
        self.build_from(env::args_os())
    }

    /// Build a FullCli by running a first round of CLI parsing with the given list of arguments.
    pub(crate) fn build_from<I, T>(mut self, args: I) -> Result<FullCli, ClapError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let args: Vec<OsString> = args.into_iter().map(|x| x.into()).collect();
        let mut command = MainConfig::augment_args(Command::new("retis")).subcommand_required(true);
        // Add thin subcommands so that the main help shows them.
        for (_, sub) in self.subcommands.iter() {
            command = command.subcommand(sub.thin().expect("thin command failed"));
        }

        // Determine the subcommand that was run while ignoring errors from yet-to-be-defined
        // arguments.
        let matches = command
            .clone()
            .ignore_errors(true)
            .try_get_matches_from(args.iter())?;

        let ran_subcommand = matches.subcommand_name();

        if ran_subcommand.is_none()
            || self
                .subcommands
                .get(&ran_subcommand.unwrap().to_string())
                .is_none()
        {
            // There is no subcommand or it's invalid. Let clap handle this error since it prints
            // nicer error messages and knows where they should be printed to.
            let err = command
                .try_get_matches_from_mut(args.iter())
                .expect_err("clap should fail with no arguments");

            match cfg!(test) {
                true => return Err(err),
                false => err.exit(),
            };
        }

        // Get main config.
        let mut main_config = MainConfig::default();
        main_config.update_from_arg_matches(&matches)?;

        // A command was run, build the FullCli so we can parse it.
        Ok(FullCli {
            args,
            main_config,
            command,
            subcommand: self
                .subcommands
                .remove(&ran_subcommand.unwrap().to_string())
                .unwrap(),
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
    /// Perform full CLI parsing and validation
    pub(crate) fn run(mut self) -> Result<CliConfig, ClapError> {
        // Replace the ran subcommand with the full subcommand.
        self.command = self
            .command
            .mut_subcommand(self.subcommand.name(), |_| self.subcommand.full().unwrap());

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
        if !subcommand.to_string().eq(self.subcommand.as_ref().name()) {
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
}

/// CliConfig represents the result of the Full CLI parsing
#[derive(Debug)]
pub(crate) struct CliConfig {
    pub(crate) main_config: MainConfig,
    pub(crate) subcommand: Box<dyn SubCommand>,
}

impl CliConfig {
    /// Creates and returns a new instance of dynamic module argument type M
    pub(crate) fn get_section<M>(&self, id: ModuleId) -> Result<M>
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

/// Create and register a ThinCli
pub(crate) fn get_cli() -> Result<ThinCli> {
    let mut cli = ThinCli::new()?;
    cli.add_subcommand(Box::new(Collect::new()?))?;
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
        fn name(&self) -> &'static str {
            "sub1"
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn thin(&self) -> Result<Command> {
            Ok(Command::new("sub1").about("does some things"))
        }
        fn full(&self) -> Result<Command> {
            Ok(Sub1::augment_args(
                Command::new("sub1")
                    .about("does some things")
                    .long_about("this is a longer description"),
            ))
        }
        fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), ClapError> {
            <Self as FromArgMatches>::update_from_arg_matches(self, matches)
        }
    }

    #[derive(Debug, Default, Args)]
    struct Sub2 {
        #[arg(id = "sub2-flag", long)]
        flag: Option<bool>,
    }

    impl SubCommand for Sub2 {
        fn new() -> Result<Self> {
            Ok(Sub2 { flag: Some(false) })
        }
        fn name(&self) -> &'static str {
            "sub2"
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn thin(&self) -> Result<Command> {
            Ok(Command::new("sub2").about("does some things"))
        }
        fn full(&self) -> Result<Command> {
            Ok(Sub2::augment_args(
                Command::new("sub2")
                    .about("does some things")
                    .long_about("this is a longer description"),
            ))
        }
        fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), ClapError> {
            <Self as FromArgMatches>::update_from_arg_matches(self, matches)
        }
    }

    #[test]
    fn cli_register_subcommands() -> Result<()> {
        let mut cli = ThinCli::new()?;
        assert!(cli.add_subcommand(Box::new(Sub1::new()?)).is_ok());
        assert!(cli.add_subcommand(Box::new(Sub2::new()?)).is_ok());
        assert!(cli.add_subcommand(Box::new(Sub1::new()?)).is_err());
        Ok(())
    }

    #[test]
    fn cli_build() -> Result<()> {
        let mut cli = ThinCli::new()?;
        assert!(cli.add_subcommand(Box::new(Sub1::new()?)).is_ok());
        assert!(cli.add_subcommand(Box::new(Sub2::new()?)).is_ok());

        let err = cli.build_from(vec!["retis", "--help"]);
        assert!(err.is_err() && err.unwrap_err().kind() == ErrorKind::DisplayHelp);

        Ok(())
    }

    #[test]
    fn cli_full_help() -> Result<()> {
        let mut cli = ThinCli::new()?;
        assert!(cli.add_subcommand(Box::new(Sub1::new()?)).is_ok());
        assert!(cli.add_subcommand(Box::new(Sub2::new()?)).is_ok());

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
        assert!(cli.add_subcommand(Box::new(Sub2::new()?)).is_ok());

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
        assert!(cli.add_subcommand(Box::new(Sub2::new()?)).is_ok());

        let cli = cli.build_from(vec!["retis", "sub1", "--noexists", "foo"]);
        assert!(cli.is_ok());
        let cli = cli.unwrap();
        assert!(cli.get_subcommand().is_ok() && cli.get_subcommand().unwrap().name().eq("sub1"));

        let res = cli.run();
        assert!(res.is_err() && res.unwrap_err().kind() == ErrorKind::UnknownArgument);

        Ok(())
    }
}
