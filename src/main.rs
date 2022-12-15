use anyhow::Result;
use log::error;
use simplelog::{Config, LevelFilter, SimpleLogger};

mod cli;
mod collect;
mod core;
mod module;
use cli::get_cli;
use collect::get_collectors;

fn main() -> Result<()> {
    let _ = SimpleLogger::init(LevelFilter::Debug, Config::default());
    let mut cli = get_cli()?.build()?;

    let command = cli.get_subcommand_mut()?;
    match command.name() {
        "collect" => {
            let mut collectors = get_collectors()?;
            collectors.register_cli(command.dynamic_mut().unwrap())?;
            let config = cli.run()?;
            collectors.init(&config)?;
            collectors.start(&config)?;
            loop {
                let event = collectors.poll_event()?;
                println!("{}", event.to_json());
            }
        }
        _ => {
            error!("not implemented");
        }
    }
    Ok(())
}
