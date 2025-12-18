//! # Cli
//!
//! Cli module, providing tools for registering and accessing command line interface arguments
//! as well as defining the subcommands that the tool supports.
use std::{
    any::Any, convert::From, env, ffi::OsString, fmt::Debug, fs, path::PathBuf, str::FromStr,
};

use anyhow::{anyhow, bail, Result};
use clap::{
    builder::PossibleValuesParser,
    error::Error as ClapError,
    error::ErrorKind,
    {ArgMatches, Args, Command, FromArgMatches, ValueEnum},
};
use log::{debug, LevelFilter};

#[cfg(feature = "benchmark")]
use crate::benchmark::cli::Benchmark;
use crate::{
    collect::cli::Collect,
    generate::Complete,
    helpers::{
        logger::{set_libbpf_rs_print_callback, Logger},
        pager::try_enable_pager,
    },
    inspect::Inspect,
    process::cli::*,
    profiles::{cli::ProfileCmd, Profile},
};

/// SubCommandRunner defines the common interface to run SubCommands.
pub(crate) trait SubCommandRunner {
    /// Run the subcommand using a cli configuration
    fn run(&mut self, cli: CliConfig) -> Result<()>;
}

/// SubCommandRunnerFunc is a wrapper for functions that implements SubCommandRunner
pub(crate) struct SubCommandRunnerFunc<F>
where
    F: Fn(CliConfig) -> Result<()>,
{
    func: F,
}

impl<F> SubCommandRunnerFunc<F>
where
    F: Fn(CliConfig) -> Result<()>,
{
    pub(crate) fn new(func: F) -> Self {
        Self { func }
    }
}

impl<F> SubCommandRunner for SubCommandRunnerFunc<F>
where
    F: Fn(CliConfig) -> Result<()>,
{
    fn run(&mut self, cli: CliConfig) -> Result<()> {
        (self.func)(cli)
    }
}

/// SubCommand defines the way to handle cli subcommands by providing a convenient way
/// of encapsulating both its arguments (i.e: clap::Command) and a way to run it
/// (provided by SubCommandRunner).
pub(crate) trait SubCommand {
    /// Allocate and return a new instance of a SubCommand.
    fn new() -> Result<Self>
    where
        Self: Sized;

    /// Returns the unique name of the subcommand.
    fn name(&self) -> String;

    /// Returns self as a mutable std::any::Any trait.
    ///
    /// This is useful for dynamically downcast the SubCommand into it's specific type to access
    /// subcommand-specific functionality.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Generate the clap Command.
    fn command(&mut self) -> Result<Command>;

    /// Updates internal structures with clap's ArgMatches.
    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), ClapError>;

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
    fn run(&mut self, main_config: &MainConfig) -> Result<()>;
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

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn command(&mut self) -> Result<Command> {
        Ok(<Self as clap::CommandFactory>::command().help_template(HELP_TEMPLATE))
    }

    fn update_from_arg_matches(&mut self, args: &ArgMatches) -> Result<(), ClapError> {
        <Self as clap::FromArgMatches>::update_from_arg_matches(self, args)
    }

    fn runner(&self) -> Result<Box<dyn SubCommandRunner>> {
        Ok(Box::new(SubCommandRunnerFunc::new(
            |mut cli: CliConfig| -> Result<()> {
                let cmd: &mut Self = cli
                    .subcommand
                    .as_any_mut()
                    .downcast_mut::<Self>()
                    .ok_or_else(|| anyhow!("wrong subcommand"))?;
                cmd.run(&cli.main_config)
            },
        )))
    }
}

#[derive(Args, Debug, Default)]
#[command(about = "Trace packets in the Linux networking stack & friends.

Retis aims at improving visibility of what happens in the Linux networking stack and different control and/or data paths, some of which can be in userspace. It works either in a single collect & display phase, or in a collect then process fashion.")]
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
        help = "Comma separated list of profiles to apply. Accepted values:
- Profile names, in which case the profile should be in either /usr/share/retis/profiles or in $HOME/.config/retis/profiles.
- Path to a profile, in which case the file should contain a single profile."
    )]
    pub(crate) profile: Vec<PathBuf>,
    #[arg(
        long,
        short = 'P',
        help = "Path to an additional directory with custom profiles. Takes precedence over built-in profiles directories."
    )]
    pub(crate) extra_profiles_dir: Option<PathBuf>,
    /// Expanded command line that was used to invoke retis
    #[arg(skip)]
    pub(crate) cmdline: String,
}

const HELP_TEMPLATE: &str = "\
{usage-heading} {usage}

{before-help}{about-with-newline}
{all-args}{after-help}\
        ";

#[derive(Debug, Default)]
pub(crate) struct RetisCli {
    subcommands: Vec<Box<dyn SubCommand>>,
}

impl RetisCli {
    /// Allocate and return a new RetisCli object that will parse the command arguments.
    pub(crate) fn new() -> Result<Self> {
        let mut cli = RetisCli::default();
        // Note the logger has not been initialized yet. Subcommand creation should
        // be as simple as possible and all logging should be delayed to
        // update_from_arg_matches.
        cli.add_subcommand(Box::new(Collect::new()?))?;
        cli.add_subcommand(Box::new(Print::new()?))?;
        cli.add_subcommand(Box::new(Sort::new()?))?;
        #[cfg(feature = "python")]
        cli.add_subcommand(Box::new(PythonCli::new()?))?;
        cli.add_subcommand(Box::new(Pcap::new()?))?;
        cli.add_subcommand(Box::new(Inspect::new()?))?;
        cli.add_subcommand(Box::new(ProfileCmd::new()?))?;
        cli.add_subcommand(Box::new(Complete::new()?))?;
        cli.add_subcommand(Box::new(PrintSchema::new()?))?;

        #[cfg(feature = "benchmark")]
        cli.add_subcommand(Box::new(Benchmark::new()?))?;

        Ok(cli)
    }

    fn add_subcommand(&mut self, sub: Box<dyn SubCommand>) -> Result<&mut Self> {
        let name = sub.name();

        if self.subcommands.iter().any(|s| s.name() == name) {
            bail!("Subcommand already registered")
        }

        self.subcommands.push(sub);
        Ok(self)
    }

    /// Build a CliConfig by parsing the arguments
    pub(crate) fn parse(self) -> CliConfig {
        self.parse_from(env::args_os()).unwrap_or_else(|e| e.exit())
    }

    /// Enhance arguments with provided profile.
    fn enhance_profile(
        main_config: &MainConfig,
        subcommand: &str,
        args: &mut Vec<OsString>,
    ) -> Result<()> {
        if main_config.profile.is_empty() {
            return Ok(());
        }

        for name in main_config.profile.iter() {
            // Profile could be a path to a file or a profile name.
            let profile = match fs::read_to_string(name) {
                Ok(s) => match Profile::from_str(&s) {
                    Ok(profile) => profile,
                    Err(e) => bail!("Could not import profile: {e}"),
                },
                _ => {
                    let name = match name.to_str() {
                        Some(name) => name,
                        None => bail!("Invalid profile name ({})", name.display()),
                    };
                    Profile::find(name, main_config.extra_profiles_dir.as_ref())?
                }
            };

            let mut extra_args = profile.cli_args(subcommand)?;
            args.append(&mut extra_args);
        }
        Ok(())
    }

    fn get_version() -> String {
        let pkg_version = option_env!("RELEASE_VERSION").unwrap_or("unspec");
        let pkg_name = option_env!("RELEASE_NAME").unwrap_or("unreleased");

        if cfg!(debug_assertions) {
            format!("{pkg_version} [dbg] (\"{pkg_name}\")")
        } else {
            format!("{pkg_version} (\"{pkg_name}\")")
        }
    }

    /// Build a CliConfig by parsing the given list of arguments.
    /// This function should be only used directly by unit tests.
    pub(crate) fn parse_from<I, T>(mut self, args: I) -> Result<CliConfig, ClapError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let mut args: Vec<OsString> = args.into_iter().map(|x| x.into()).collect();

        // Build the main command.
        let mut command = MainConfig::augment_args(Command::new("retis"))
            .version(Self::get_version())
            .term_width(80)
            .disable_help_subcommand(true)
            .infer_subcommands(true)
            .subcommand_required(true)
            .help_template(HELP_TEMPLATE);

        // Add full subcommands so that the main help shows them.
        for sub in self.subcommands.iter_mut() {
            command = command.subcommand(sub.command().expect("command failed"));
        }

        // Run command parsing once before profile expansion to extract the logging level and the
        // subcommand name (needed to know what part of the profile we need to expand).
        let matches = command.clone().try_get_matches_from(args.iter())?;

        let mut main_config = MainConfig::default();
        main_config.update_from_arg_matches(&matches)?;

        let log_level = main_config.log_level.as_str();
        let log_level = LevelFilter::from_str(log_level).map_err(|e| {
            command.error(
                ErrorKind::InvalidValue,
                format!("Invalid log_level: {log_level} ({e})"),
            )
        })?;
        let logger = Logger::init(log_level).map_err(|e| {
            command.error(
                ErrorKind::InvalidValue,
                format!("Invalid log_level: {log_level} ({e})"),
            )
        })?;
        set_libbpf_rs_print_callback(log_level);

        // Retrieve the subcommand that was run.
        let mut subcommand = matches
            .subcommand_name()
            .and_then(|name| self.subcommands.drain(..).find(|s| s.name() == name))
            .ok_or_else(||
                // There is no subcommand or it's invalid. Re-run the match to generate
                // the right clap error that to be printed nicely.
                command
                    .try_get_matches_from_mut(args.iter())
                    .expect_err("clap should fail with no arguments"))?;

        match subcommand.name().as_str() {
            // Try setting up the pager for a selected subset of commands.
            // This needs to be done before the final round of cli parsing because logs can be emitted
            // and we need to redirect them to stdout if pager is active.
            "print" | "sort" => {
                try_enable_pager(&logger);
            }
            _ => (),
        }

        // Expand profile arguments.
        RetisCli::enhance_profile(&main_config, subcommand.name().as_str(), &mut args)
            .map_err(|err| command.error(ErrorKind::InvalidValue, format!("{err}")))?;

        let cmdline = args
            .iter()
            .map(|o| o.as_os_str().to_str().unwrap_or("<encoding error>"))
            .collect::<Vec<&str>>()
            .join(" ");

        debug!("Resulting CLI arguments: {cmdline}");

        // Final round of parsing.
        let matches = match cfg!(test) {
            true => command.try_get_matches_from_mut(args.iter())?,
            false => command
                .try_get_matches_from_mut(args.iter())
                .unwrap_or_else(|e| e.exit()),
        };
        let (_, matches) = matches
            .subcommand()
            .expect("full parsing did not find subcommand");

        // Update subcommand options.
        match cfg!(test) {
            true => subcommand.update_from_arg_matches(matches)?,
            false => subcommand
                .update_from_arg_matches(matches)
                .unwrap_or_else(|e| e.exit()),
        }

        // Store the command line for use in initial event
        main_config.cmdline = cmdline;

        Ok(CliConfig {
            command,
            main_config,
            subcommand,
        })
    }
}

/// CliConfig represents the result of the RetisCli
#[derive(Debug)]
pub(crate) struct CliConfig {
    /// The underlying clap.Command object
    pub(crate) command: Command,
    /// Main configuration options
    pub(crate) main_config: MainConfig,
    /// Subcommand that was run
    pub(crate) subcommand: Box<dyn SubCommand>,
}

/// Type of the "format" argument.
// It is an enum that maps 1:1 with the formats defined in events library.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub(crate) enum CliDisplayFormat {
    SingleLine,
    #[default]
    MultiLine,
}
