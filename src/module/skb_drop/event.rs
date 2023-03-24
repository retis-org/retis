use anyhow::Result;
use plain::Plain;
use serde::{Deserialize, Serialize};

use crate::{
    core::events::{
        bpf::{parse_single_raw_section, BpfRawSection},
        *,
    },
    module::ModuleId,
    EventSection, EventSectionFactory,
};

// Skb drop event section. Same as the event from BPF, please keep in sync with
// its BPF counterpart.
#[derive(Default, Deserialize, Serialize, EventSection, EventSectionFactory)]
#[repr(C, packed)]
pub(crate) struct SkbDropEvent {
    /// Reason why a packet was freed/dropped. Only reported from specific
    /// functions. See `enum skb_drop_reason` in the kernel.
    pub(crate) drop_reason: u32,
}

unsafe impl Plain for SkbDropEvent {}

impl RawEventSectionFactory for SkbDropEvent {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        Ok(Box::new(parse_single_raw_section::<Self>(
            ModuleId::SkbDrop,
            raw_sections,
        )?))
    }
}
