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

// Tracking event section. Same as the event from BPF, please keep in sync with
// its BPF counterpart.
/// For more information of how the tracking logic is designed and how it can be
/// used, please see `module::skb_tracking` documentation.
///
/// Tl;dr; the tracking unique id is `(timestamp, orig_head)` and `skb` can be
/// used to distinguished between clones.
#[event_section]
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

#[derive(Default)]
#[event_section_factory(SkbTrackingEvent)]
pub(crate) struct SkbTrackingEventFactory {}

impl RawEventSectionFactory for SkbTrackingEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        Ok(Box::new(parse_single_raw_section::<SkbTrackingEvent>(
            ModuleId::SkbTracking,
            raw_sections,
        )?))
    }
}
