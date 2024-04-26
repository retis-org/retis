use anyhow::Result;

use super::{tracking_hook, SkbTrackingEventFactory};
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::probe::{manager::ProbeBuilderManager, Hook},
    events::EventSectionFactory,
    module::{Module, ModuleId},
};

#[derive(Default)]
pub(crate) struct SkbTrackingModule {}

impl Collector for SkbTrackingModule {
    fn new() -> Result<Self> {
        Ok(Self::default())
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct sk_buff *"])
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(ModuleId::SkbTracking)
    }

    fn init(&mut self, _: &CliConfig, probes: &mut ProbeBuilderManager) -> Result<()> {
        probes.register_kernel_hook(Hook::from(tracking_hook::DATA))
    }
}

impl Module for SkbTrackingModule {
    fn collector(&mut self) -> &mut dyn Collector {
        self
    }
    fn section_factory(&self) -> Result<Box<dyn EventSectionFactory>> {
        Ok(Box::new(SkbTrackingEventFactory {}))
    }
}
