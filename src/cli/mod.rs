//! # Cli
//!
//! Cli module, providing tools for registering and accessing command line interface arguments
//! as well as defining the subcommands that the tool supports.
//!
//! The main feature that this module adds on top of clap's CLI parsing is the ability to
//! dynamically register module-specific arguments in a way that does not require this module to
//! depend on the rest. In addition, since the Cli supports subcommands, it's possible to only
//! register arguments to the subcommand that is actually run.
//!
//! In order to achieve this, the command line arguments have to be parsed twice. One first round,
//! called "thin", just validates the subcommand that was run. After that, modules can know which
//! subcommand was run and register arguments to it before the final argument parsing and
//! validation, called "full" is performed.

#[allow(clippy::module_inception)]
pub(crate) mod cli;
pub(crate) mod dynamic;

// Re-export cli.rs
pub(crate) use cli::*;
