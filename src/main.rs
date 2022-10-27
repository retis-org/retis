use anyhow::Result;

mod collector;
mod core;
use collector::get_collectors;

fn main() -> Result<()> {
    let mut collectors = get_collectors()?;
    collectors.init()?;
    collectors.start()?;
    Ok(())
}
