use anyhow::{bail, Result};
use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

mod cli;
mod collect;
mod core;
mod module;
mod process;
mod profiles;

use crate::{cli::get_cli, core::inspect::init_inspector, module::get_modules};

// Re-export derive macros.
use retis_derive::*;

const VERSION_NAME: &str = "pizza";

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
