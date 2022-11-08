use anyhow::Result;

use crate::collector::Collector;
use crate::core::probe::kernel;

pub(in crate::collector) struct SkbCollector {}

impl Collector for SkbCollector {
    fn new() -> Result<SkbCollector> {
        Ok(SkbCollector {})
    }

    fn name(&self) -> &'static str {
        "skb"
    }

    fn init(&mut self, _kernel: &mut kernel::Kernel) -> Result<()> {
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}
