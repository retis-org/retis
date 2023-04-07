use anyhow::Result;
use plain::Plain;

use crate::{
    core::events::{
        bpf::{parse_single_raw_section, BpfRawSection},
        *,
    },
    event_section, event_section_factory,
    module::ModuleId,
};

// Skb drop event section. Same as the event from BPF, please keep in sync with
// its BPF counterpart.
#[event_section]
#[repr(C, packed)]
pub(crate) struct SkbDropEvent {
    /// Reason why a packet was freed/dropped. Only reported from specific
    /// functions. See `enum skb_drop_reason` in the kernel.
    pub(crate) drop_reason: u32,
}

unsafe impl Plain for SkbDropEvent {}

#[derive(Default)]
#[event_section_factory(SkbDropEvent)]
pub(crate) struct SkbDropEventFactory {}

impl RawEventSectionFactory for SkbDropEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        Ok(Box::new(parse_single_raw_section::<SkbDropEvent>(
            ModuleId::SkbDrop,
            raw_sections,
        )?))
    }
}
