use anyhow::{bail, Result};
use log::{debug, info, warn};
use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

mod cli;
mod collect;
mod core;
mod module;
mod process;
mod profiles;

#[cfg(feature = "benchmark")]
mod benchmark;

use crate::{cli::get_cli, core::inspect::init_inspector, module::get_modules};

// Re-export derive macros.
use retis_derive::*;

const VERSION_NAME: &str = "pizza margherita";

fn main() -> Result<()> {
    let mut cli = get_cli()?.build()?;

    let log_level = match cli.main_config.log_level.as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        x => bail!("Invalid log_level: {}", x),
    };
    TermLogger::init(
        log_level,
        Config::default(),
        TerminalMode::Stderr, // Use stderr so logs do not conflict w/ other output.
        ColorChoice::Auto,
    )?;
    set_libbpf_rs_print_callback(log_level);

    // Save the --kconf option value before using the cli object to dispatch the
    // command.
    let kconf_opt = cli.main_config.kconf.clone();

    // Step 3: get the modules.
    let modules = get_modules()?;

    // Step 4: dispatch the command.
    let command = cli.get_subcommand_mut()?;
    if command.name() == "collect" {
        // If the user provided a custom kernel config location, use it early to
        // initialize the inspector. As the inspector is only used by the
        // collect command, only initialize it there for now.
        if let Some(kconf) = &kconf_opt {
            init_inspector(kconf)?;
        }
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
            libbpf_rs::PrintLevel::Debug => debug!("{msg}"),
            libbpf_rs::PrintLevel::Info => info!("{msg}"),
            libbpf_rs::PrintLevel::Warn => warn!("{msg}"),
        }
    };

    libbpf_rs::set_print(match level {
        LevelFilter::Error | LevelFilter::Off => None,
        LevelFilter::Warn => Some((libbpf_rs::PrintLevel::Warn, libbpf_rs_print)),
        LevelFilter::Info => Some((libbpf_rs::PrintLevel::Info, libbpf_rs_print)),
        LevelFilter::Debug | LevelFilter::Trace => {
            Some((libbpf_rs::PrintLevel::Debug, libbpf_rs_print))
        }
    });
}
