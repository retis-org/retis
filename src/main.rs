use anyhow::Result;

mod collector;
use collector::get_collectors;
mod core;

fn main() -> Result<()> {
    let mut collectors = get_collectors()?;
    collectors.init()?;
    collectors.start()?;
    Ok(())
}
