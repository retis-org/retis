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

use crate::{cli::RetisCli, core::inspect::init_inspector, helpers::pager::try_enable_pager};

// Re-export events crate. It's not really an import but a re-export so events appear as module
// inside the crate rather than an external crate. However, clippy doesn't like it.
#[allow(clippy::single_component_path_imports)]
use events;
// Re-export derive macros.
use retis_derive::*;

fn main() -> Result<()> {
    let cli = RetisCli::new()?.parse();

    // Save the --kconf option value before using the cli object to dispatch the
    // command.
    let kconf_opt = cli.main_config.kconf.clone();

    // Per-command early fixups.
    match cli.subcommand.name().as_str() {
        // If the user provided a custom kernel config location, use it early to
        // initialize the inspector. As the inspector is only used by the
        // collect command, only initialize it there for now.
        "collect" => {
            if let Some(kconf) = &kconf_opt {
                init_inspector(kconf)?;
            }
        }
        // Try setting up the pager for a selected subset of commands.
        "print" | "sort" => {
            try_enable_pager(&cli.logger.clone());
        }
        _ => (),
    }

    let mut runner = cli.subcommand.runner()?;
    runner.run(cli)?;
    Ok(())
}
