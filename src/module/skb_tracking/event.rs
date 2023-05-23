use anyhow::Result;
use plain::Plain;

use crate::{
    core::events::{
        bpf::{parse_single_raw_section, BpfRawSection},
        *,
    },
    event_section, event_section_factory, EventSectionDisplay,
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
#[derive(EventSectionDisplay)]
#[repr(C)]
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

#[allow(dead_code)]
impl SkbTrackingEvent {
    /// Get the tracking id.
    pub(crate) fn tracking_id(&self) -> u128 {
        (self.timestamp as u128) << 64 | self.orig_head as u128
    }

    /// Check if two tracking event sections are from related skbs, including
    /// clones.
    pub(crate) fn r#match(&self, other: &SkbTrackingEvent) -> bool {
        self.tracking_id() == other.tracking_id()
    }

    /// Check if two tracking event sections are from the exact same skb.
    pub(crate) fn strict_match(&self, other: &SkbTrackingEvent) -> bool {
        self.r#match(other) && self.skb == other.skb
    }
}

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
