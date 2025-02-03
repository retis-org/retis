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

use crate::{cli::RetisCli, helpers::pager::try_enable_pager};

// Re-export events crate. It's not really an import but a re-export so events appear as module
// inside the crate rather than an external crate. However, clippy doesn't like it.
#[allow(clippy::single_component_path_imports)]
use events;
// Re-export derive macros.
use retis_derive::*;

fn main() -> Result<()> {
    let cli = RetisCli::new()?.parse();

    // Per-command early fixups.
    match cli.subcommand.name().as_str() {
        // Try setting up the pager for a selected subset of commands.
        // This needs to be done before the final round of cli parsing because logs can be emitted
        // and we need to redirect them to stdout if pager is active.
        "print" | "sort" => {
            try_enable_pager(&cli.logger.clone());
        }
        _ => (),
    }

    let mut runner = cli.subcommand.runner()?;
    runner.run(cli)?;
    Ok(())
}
