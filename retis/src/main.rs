use anyhow::Result;

mod bindings;
mod cli;
mod collect;
mod core;
mod generate;
mod helpers;
mod inspect;
mod process;
mod profiles;

#[cfg(feature = "benchmark")]
mod benchmark;

use crate::cli::RetisCli;

// Re-export events crate. It's not really an import but a re-export so events appear as module
// inside the crate rather than an external crate. However, clippy doesn't like it.
#[allow(clippy::single_component_path_imports)]
use events;
// Re-export derive macros.
use retis_derive::*;

fn main() -> Result<()> {
    let cli = RetisCli::new()?.parse();

    let mut runner = cli.subcommand.runner()?;
    runner.run(cli)?;
    Ok(())
}
