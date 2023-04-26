use anyhow::{bail, Result};
use log::error;
use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

mod cli;
mod collect;
mod core;
mod module;
use cli::get_cli;
use collect::get_collectors;

// Re-export derive macros.
use retis_derive::*;

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

    let command = cli.get_subcommand_mut()?;
    match command.name() {
        "collect" => {
            let mut collectors = get_collectors(cli)?;

            collectors.init()?;
            collectors.start()?;

            // Starts a loop.
            collectors.process()?;
            collectors.stop()?;
        }
        _ => {
            error!("not implemented");
        }
    }
    Ok(())
}
