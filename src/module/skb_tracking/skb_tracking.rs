use anyhow::Result;

use super::tracking_hook;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::probe::{manager::ProbeManager, Hook},
    module::ModuleId,
};

#[derive(Default)]
pub(crate) struct SkbTrackingCollector {}

impl Collector for SkbTrackingCollector {
    fn new() -> Result<SkbTrackingCollector> {
        Ok(SkbTrackingCollector::default())
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct sk_buff *"])
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(ModuleId::SkbTracking)
    }

    fn init(&mut self, _: &CliConfig, probes: &mut ProbeManager) -> Result<()> {
        probes.register_kernel_hook(Hook::from(tracking_hook::DATA))
    }
}
