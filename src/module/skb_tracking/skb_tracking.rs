use anyhow::Result;

use super::tracking_hook;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::probe::{manager::ProbeBuilderManager, Hook},
    event_section, event_section_factory,
    events::{
        bpf::{parse_single_raw_section, BpfRawSection},
        *,
    },
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

#[derive(Default)]
#[event_section_factory(SkbTrackingEvent)]
pub(crate) struct SkbTrackingEventFactory {}

impl RawEventSectionFactory for SkbTrackingEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let event =
            parse_single_raw_section::<SkbTrackingEvent>(ModuleId::SkbTracking, &raw_sections)?;

        Ok(Box::new(*event))
    }
}
