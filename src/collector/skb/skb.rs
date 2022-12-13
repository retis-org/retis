use anyhow::Result;

use crate::cli::{dynamic::DynamicCommand, CliConfig};
use crate::collector::Collector;
use crate::core::probe::kernel;

const SKB_COLLECTOR: &str = "skb";

pub(in crate::collector) struct SkbCollector {}

impl Collector for SkbCollector {
    fn new() -> Result<SkbCollector> {
        Ok(SkbCollector {})
    }

    fn name(&self) -> &'static str {
        SKB_COLLECTOR
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(SKB_COLLECTOR)
    }

    fn init(&mut self, _: &CliConfig, _kernel: &mut kernel::Kernel) -> Result<()> {
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}
