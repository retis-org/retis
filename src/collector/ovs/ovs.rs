use anyhow::Result;

use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collector::Collector,
    core::{events::bpf::BpfEvents, probe::kernel},
};

const OVS_COLLECTOR: &str = "ovs";

pub(in crate::collector) struct OvsCollector {}

impl Collector for OvsCollector {
    fn new() -> Result<OvsCollector> {
        Ok(OvsCollector {})
    }

    fn name(&self) -> &'static str {
        OVS_COLLECTOR
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(OVS_COLLECTOR)
    }

    fn init(
        &mut self,
        _: &CliConfig,
        _kernel: &mut kernel::Kernel,
        _events: &mut BpfEvents,
    ) -> Result<()> {
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}
