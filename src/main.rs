use anyhow::Result;

pub(crate) mod collector;
use collector::get_collectors;

fn main() -> Result<()> {
    let mut collectors = get_collectors()?;
    collectors.init()?;
    collectors.start()?;
    Ok(())
}
