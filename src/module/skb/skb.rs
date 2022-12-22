use anyhow::Result;

use super::skb_hook;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{events::bpf::BpfEvents, probe::{ProbeManager, Hook}},
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
        Some(vec!["struct sk_buff *"])
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(SKB_COLLECTOR)
    }

    fn init(
        &mut self,
        _: &CliConfig,
        probes: &mut ProbeManager,
        _events: &mut BpfEvents,
    ) -> Result<()> {
        probes.register_kernel_hook(Hook::from(skb_hook::DATA))?;
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}
