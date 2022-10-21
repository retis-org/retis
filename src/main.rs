use anyhow::Result;

mod collector;
mod config;
mod core;
use collector::get_collectors;
use config::Cli;

fn main() -> Result<()> {
    let mut cli = Cli::new()?;
    let mut collectors = get_collectors(&mut cli)?;
    cli.parse()?;
    collectors.init(&mut cli)?;
    collectors.start()?;
    Ok(())
}
