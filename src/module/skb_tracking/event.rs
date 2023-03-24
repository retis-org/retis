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

// Tracking event section. Same as the event from BPF, please keep in sync with
// its BPF counterpart.
/// For more information of how the tracking logic is designed and how it can be
/// used, please see `module::skb_tracking` documentation.
///
/// Tl;dr; the tracking unique id is `(timestamp, orig_head)` and `skb` can be
/// used to distinguished between clones.
#[derive(Default, Deserialize, Serialize, EventSection, EventSectionFactory)]
#[repr(C, packed)]
pub(crate) struct SkbTrackingEvent {
    /// Head of buffer (`skb->head`) when the packet was first seen by the
    /// tracking logic.
    pub(crate) orig_head: u64,
    /// Timestamp of when the tracking logic first saw the packet.
    pub(crate) timestamp: u64,
    /// Socket buffer (`skb`) address of the current packet.
    pub(crate) skb: u64,
}

unsafe impl Plain for SkbTrackingEvent {}

impl RawEventSectionFactory for SkbTrackingEvent {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        Ok(Box::new(parse_single_raw_section::<Self>(
            ModuleId::SkbTracking,
            raw_sections,
        )?))
    }
}
