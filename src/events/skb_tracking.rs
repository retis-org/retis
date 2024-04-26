use anyhow::Result;

use std::{
    cmp::{Eq, Ord, Ordering, PartialEq},
    fmt,
};

use super::*;
use crate::event_section;

// Tracking event section. Same as the event from BPF, please keep in sync with
// its BPF counterpart.
/// For more information of how the tracking logic is designed and how it can be
/// used, please see `module::skb_tracking` documentation.
///
/// Tl;dr; the tracking unique id is `(timestamp, orig_head)` and `skb` can be
/// used to distinguished between clones.
#[derive(Copy, PartialEq)]
#[event_section]
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

impl EventFmt for SkbTrackingEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        write!(f, "#{:x} (skb {:x})", self.tracking_id(), self.skb)
    }
}

/// Tracking event section. Generated at postprocessing with combined skb and ovs
/// tracking information.
#[event_section]
pub(crate) struct TrackingInfo {
    /// Tracking information of the original packet.
    pub(crate) skb: SkbTrackingEvent,
    /// The index in the event series.
    pub(crate) idx: u32,
}

impl Eq for TrackingInfo {}

impl PartialEq for TrackingInfo {
    fn eq(&self, other: &Self) -> bool {
        self.skb.tracking_id().eq(&other.skb.tracking_id())
    }
}

impl PartialOrd for TrackingInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for TrackingInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.skb
            .timestamp
            .cmp(&other.skb.timestamp)
            .then_with(|| self.skb.orig_head.cmp(&other.skb.orig_head))
    }
}

impl EventFmt for TrackingInfo {
    fn event_fmt(&self, f: &mut fmt::Formatter, format: DisplayFormat) -> fmt::Result {
        write!(f, "{} n {}", self.skb.display(format), self.idx)
    }
}

impl TrackingInfo {
    pub(crate) fn new(track: &SkbTrackingEvent) -> Result<Self> {
        Ok(TrackingInfo {
            skb: *track,
            idx: 0,
        })
    }
}
