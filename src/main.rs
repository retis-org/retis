use std::str::FromStr;

use anyhow::{anyhow, Result};
use log::{info, trace, warn, LevelFilter};

mod cli;
mod collect;
mod core;
mod generate;
mod helpers;
mod inspect;
mod module;
mod process;
mod profiles;

#[cfg(feature = "benchmark")]
mod benchmark;

use crate::{
    cli::get_cli,
    core::inspect::init_inspector,
    helpers::{logger::Logger, pager::try_enable_pager},
    module::get_modules,
};

// Re-export events crate. It's not really an import but a re-export so events appear as module
// inside the crate rather than an external crate. However, clippy doesn't like it.
#[allow(clippy::single_component_path_imports)]
use events;
// Re-export derive macros.
use retis_derive::*;

fn main() -> Result<()> {
    let mut cli = get_cli()?.build();
    let log_level = cli.main_config.log_level.as_str();
    let log_level = LevelFilter::from_str(log_level)
        .map_err(|e| anyhow!("Invalid log_level: {log_level} ({e})"))?;
    let logger = Logger::init(log_level)?;
    set_libbpf_rs_print_callback(log_level);

    // Save the --kconf option value before using the cli object to dispatch the
    // command.
    let kconf_opt = cli.main_config.kconf.clone();

    // Step 3: get the modules.
    let modules = get_modules()?;

    // Step 4: dispatch the command.
    let command = cli.get_subcommand_mut()?;

    // Per-command early fixups.
    match command.name().as_str() {
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
            try_enable_pager(&logger);
        }
        _ => (),
    }

    let mut runner = command.runner()?;
    runner.check_prerequisites()?;
    runner.run(cli, modules)?;
    Ok(())
}

fn set_libbpf_rs_print_callback(level: LevelFilter) {
    let libbpf_rs_print = |level, msg: String| {
        let msg = msg.trim_end_matches('\n');
        match level {
            libbpf_rs::PrintLevel::Debug => trace!("{msg}"),
            libbpf_rs::PrintLevel::Info => info!("{msg}"),
            libbpf_rs::PrintLevel::Warn => warn!("{msg}"),
        }
    };

    libbpf_rs::set_print(match level {
        LevelFilter::Error | LevelFilter::Off => None,
        LevelFilter::Warn => Some((libbpf_rs::PrintLevel::Warn, libbpf_rs_print)),
        LevelFilter::Info | LevelFilter::Debug => {
            Some((libbpf_rs::PrintLevel::Info, libbpf_rs_print))
        }
        LevelFilter::Trace => Some((libbpf_rs::PrintLevel::Debug, libbpf_rs_print)),
    });
}
