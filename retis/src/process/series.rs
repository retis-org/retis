//! Series
//!
//! EventSeries is a collection of sorted Events.
//!
//! Events can be added to EventSeries in any order and it will internally arrange them based on
//! their TrackingInfo.

use std::collections::{BTreeMap, HashMap, VecDeque};

use anyhow::{anyhow, Result};

use crate::events::*;

#[derive(Default)]
pub(crate) struct EventSorter {
    series: BTreeMap<TrackingInfo, Vec<Event>>,
    untracked: VecDeque<Event>,
    n_events: usize,
    flow_info: HashMap<FlowId, OvsFlowInfoEvent>,
}

impl EventSorter {
    /// Creates a empty EventSorter.
    pub(crate) fn new() -> Self {
        EventSorter {
            series: BTreeMap::new(),
            untracked: VecDeque::new(),
            n_events: 0,
            flow_info: HashMap::new(),
        }
    }

    /// Returns the total number of Events in the EventSorter.
    pub(crate) fn len(&self) -> usize {
        self.n_events
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

    /// Adds an event to the EventSorter.
    pub(crate) fn add(&mut self, event: Event) {
        // Store FlowInfoEvents.
        if let Some(flow_info) = event.get_section::<OvsFlowInfoEvent>(SectionId::OvsFlowInfo) {
            self.flow_info
                .insert(flow_info.flow_id(), flow_info.clone());
        }

        match event.get_section::<TrackingInfo>(SectionId::Tracking) {
            Some(track) => match self.series.get_mut(track) {
                Some(series) => {
                    series.push(event);
                }
                None => {
                    self.series.insert(track.clone(), vec![event]);
                }
            },
            None => {
                self.untracked.push_back(event);
            }
        }
        self.n_events += 1;
    }

    /// Removes and returns Events of the oldest series in a Vector.
    pub(crate) fn pop_oldest(&mut self) -> Result<Option<EventSeries>> {
        Ok(if self.n_events == 0 {
            None
        } else if self.untracked.is_empty() {
            self.pop_oldest_series()
        } else if self.series.is_empty() {
            self.pop_oldest_untracked().map(|e| vec![e])
        } else {
            // Pop whatever is oldest
            // It's safe to unwrap because we've already checked both series and untracked are
            // non-empty.
            if self.series.iter().next().unwrap().0.skb.timestamp
                < self
                    .untracked
                    .front()
                    .unwrap()
                    .get_section::<CommonEvent>(SectionId::Common)
                    .map(|c| c.timestamp)
                    .ok_or_else(|| anyhow!("malformed event: no common section"))?
            {
                self.pop_oldest_series()
            } else {
                self.pop_oldest_untracked().map(|e| vec![e])
            }
        }
        .map(|v| EventSeries { events: v }))
    }

    fn pop_oldest_untracked(&mut self) -> Option<Event> {
        match self.untracked.pop_front() {
            Some(e) => {
                self.n_events -= 1;
                Some(e)
            }
            None => None,
        }
    }

    fn pop_oldest_series(&mut self) -> Option<Vec<Event>> {
        // TODO: Use pop_first when it's stable to avoid having to clone the key.
        match self.series.iter().next() {
            Some((key, _)) => {
                let key = key.clone();
                match self.series.remove(&key) {
                    Some(mut series) => {
                        self.n_events -= series.len();
                        // Enrich flow lookups at dequeue time to catch FlowInfoEvents that came
                        // after the Lookup one.
                        series
                            .iter_mut()
                            .filter_map(|e| e.get_section_mut::<OvsEvent>(SectionId::Ovs))
                            .for_each(|o| self.enrich_ovs_lookup(o));
                        Some(series)
                    }
                    None => None,
                }
            }
            None => None,
        }
    }
}
