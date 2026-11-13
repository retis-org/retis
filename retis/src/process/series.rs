//! Helpers to process events into series.

use std::collections::{BTreeMap, HashMap, VecDeque};

use crate::events::*;

// Bucket of events corresponding to a single timestamp:
// - Events might be generated at the same time (tracked + untracked).
// - Events in a series are grouped by the lowest timestamp.
#[derive(Default)]
struct TimestampBucket {
    tracked: HashMap<TrackingInfo, BTreeMap<u64, Event>>,
    untracked: VecDeque<Event>,
}

/// Events added to the [`EventSorter`] are sorted based on their timestamp.
///
/// If events contain tracking information ([`TrackingInfo`]), they are also
/// grouped into series and sorted twice (in the series and as a series). This
/// tracking information is only added and used when dealing with series, making
/// this behavior optional and up to the caller.
///
/// When dealing with tracked events, we don't need to fixup the tracking
/// information if events of a series are not in order. This is because the
/// tracking information already contains the timestamp of the first time we saw
/// an skb in the eBPF side (thus before reordering can happen). We have to
/// fixup the tracking index of events in a series though.
#[derive(Default)]
pub(crate) struct EventSorter {
    events: BTreeMap<u64, TimestampBucket>,
    track_ts: HashMap<TrackingInfo, u64>,
    n_events: usize,
    // Map of OvS flow info events, used to fixup events before consuming them.
    flow_info: HashMap<FlowId, OvsFlowInfoEvent>,
}

impl EventSorter {
    /// Adds an event to the EventSorter.
    pub(crate) fn add(&mut self, event: Event) {
        // Store FlowInfoEvents.
        if let Some(flow_info) = event.ovs_detrace.as_ref() {
            self.flow_info
                .insert(flow_info.flow_id(), flow_info.clone());
        }

        let ts = self.get_timestamp(&event);
        let bucket = self.events.entry(ts).or_default();

        match &event.tracking {
            Some(track) => {
                self.track_ts.insert(track.clone(), ts);
                bucket.tracked.entry(track.clone()).or_default().insert(
                    match &event.common {
                        Some(common) => common.timestamp,
                        None => 0,
                    },
                    event,
                );
            }
            None => bucket.untracked.push_back(event),
        }

        self.n_events += 1;
    }

    /// Return the oldest event series available. Multiple series can be
    /// returned if they share the same timestamp.
    pub(crate) fn pop(&mut self) -> Vec<EventSeries> {
        let mut series = Vec::new();

        if let Some((_, mut bucket)) = self.events.pop_first() {
            bucket.untracked.drain(..).for_each(|e| {
                self.n_events -= 1;
                series.push(EventSeries { events: vec![e] });
            });

            bucket.tracked.drain().for_each(|(track, es)| {
                self.track_ts.remove(&track);
                let mut events = es.into_values().collect::<Vec<_>>();

                let mut idx = 0;
                events.iter_mut().for_each(|e| {
                    // We know it has a tracking info for sure.
                    e.tracking.as_mut().unwrap().idx = idx;
                    idx += 1;

                    // Enrich flow lookups at dequeue time to catch
                    // FlowInfoEvents that came after the Lookup one.
                    if let Some(ovs) = e.ovs.as_mut() {
                        self.enrich_ovs_lookup(ovs);
                    }
                });

                self.n_events -= events.len();
                series.push(EventSeries { events });
            });
        }

        series
    }

    /// Returns the total number of Events in the EventSorter.
    pub(crate) fn len(&self) -> usize {
        self.n_events
    }

    fn get_timestamp(&self, event: &Event) -> u64 {
        if let Some(track) = &event.tracking {
            if let Some(ts) = self.track_ts.get(track) {
                return *ts;
            }
        }

        if let Some(common) = &event.common {
            return common.timestamp;
        }

        // Something is off.
        0
    }

    fn enrich_ovs_lookup(&mut self, ovs: &mut OvsEvent) {
        if let OvsEvent::DpLookup {
            flow_lookup: lookup,
        } = ovs
        {
            if let Some(info) = self.flow_info.get(&lookup.flow_id()) {
                lookup.dpflow = info.dpflow.clone();
                lookup.ofpflows = info.ofpflows.clone();
            }
        }
    }
}
