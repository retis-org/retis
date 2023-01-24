use anyhow::Result;

use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{events::bpf::BpfEvents, probe::ProbeManager},
};

const SKB_COLLECTOR: &str = "skb";

pub(crate) struct SkbCollector {}

impl Collector for SkbCollector {
    fn new() -> Result<SkbCollector> {
        Ok(SkbCollector {})
    }

    fn name(&self) -> &'static str {
        SKB_COLLECTOR
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        None
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(SKB_COLLECTOR)
    }

    fn init(
        &mut self,
        _: &CliConfig,
        _probes: &mut ProbeManager,
        _events: &mut BpfEvents,
    ) -> Result<()> {
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}
