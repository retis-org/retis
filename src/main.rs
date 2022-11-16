use anyhow::Result;

mod cli;
mod collector;
mod core;
use cli::get_cli;
use collector::get_collectors;

fn main() -> Result<()> {
    let _ = get_cli();
    let mut collectors = get_collectors()?;
    collectors.init()?;
    collectors.start()?;
    Ok(())
}
