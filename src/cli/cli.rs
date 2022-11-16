//! # Cli
//!
//! Cli module, providing tools for registering and accessing command line interface arguments
//! as well as defining the subcommands that the tool supports.
#![allow(dead_code)] // FIXME
                     //
use anyhow::Result;
use std::any::Any;

use clap::error::Error as ClapError;
use clap::{error::ErrorKind, ArgMatches, Args, Command};

use super::dynamic::DynamicCommand;

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

/// Trace packets on the Linux kernel
///
/// packet-tracer is a tool for capturing networking-related events from the system using ebpf and analyzing them.
#[derive(Args, Default, Debug)]
pub(crate) struct MainConfig {}

/// ThinCli handles the first (a.k.a "thin") round of Command Line Interface parsing.
///
/// During this phase, SubCommands can be added. After all SubCommands have been added, the build()
/// method will run the thin CLI parsing that does not perform dynamic subcommand argument
/// validation and yield a FullCli object to represent the results.
pub(crate) struct ThinCli {}

impl ThinCli {
    /// Builds a FullCli by running a first round of CLI parsing without subcommand argument
    /// validation.
    pub(crate) fn build(self) -> Result<FullCli, ClapError> {
        Err(ClapError::new(ErrorKind::DisplayHelp))
    }
}

/// FullCli handles the second (a.k.a "full") round of Command Line Interface parsing.
///
/// When a FullCli is created it can be used to dynamically add command line arguments to the
/// SubCommand that was ran. After this phase, a call to run() will perform the full argument
/// validation.
pub(crate) struct FullCli {}

impl FullCli {
    /// Perform full CLI parsing and validation
    pub(crate) fn run(self) -> Result<CliResults, ClapError> {
        Err(ClapError::new(ErrorKind::DisplayHelp))
    }
}

/// CliResult represents the result of the Full CLI parsing
pub(crate) struct CliResults {}

/// Create and register a ThinCli
pub(crate) fn get_cli() -> Result<ThinCli> {
    Ok(ThinCli {})
}
