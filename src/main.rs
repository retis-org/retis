use anyhow::{bail, Result};
use log::error;
use simplelog::{Config, LevelFilter, SimpleLogger};

mod cli;
mod collect;
mod core;
mod module;
use cli::get_cli;
use collect::get_collectors;

fn main() -> Result<()> {
    let mut cli = get_cli()?.build()?;

    let log_level = match cli.main_config.log_level.as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        x => bail!("Invalid log_level: {}", x),
    };
    let _ = SimpleLogger::init(log_level, Config::default());

    let command = cli.get_subcommand_mut()?;
    match command.name() {
        "collect" => {
            let mut collectors = get_collectors()?;

            collectors.register_cli(command.dynamic_mut().unwrap())?;
            let config = cli.run()?;

            collectors.init(&config)?;
            collectors.start(&config)?;

            // Starts a loop.
            collectors.process(&config)?;
        }
        _ => {
            error!("not implemented");
        }
    }
    Ok(())
}
