//! Series
//!
//! EventSeries is a collection of sorted Events.
//!
//! Events can be added to EventSeries in any order and it will internally arrange them based on
//! their TrackingInfo.

use std::collections::{BTreeMap, VecDeque};

use super::tracking::TrackingInfo;
use anyhow::{anyhow, Result};
use log::warn;

use crate::{
    core::events::{bpf::CommonEvent, Event},
    module::ModuleId,
};

/// A set of sorted Events with the same tracking id.
#[derive(Default)]
pub(crate) struct EventSeries {
    /// Events that comprise the Series.
    pub(crate) events: Vec<Event>,
}

impl EventSeries {
    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Array(self.events.iter().map(|e| e.to_json()).collect())
    }
}

#[derive(Default)]
pub(crate) struct EventSorter {
    series: BTreeMap<TrackingInfo, Vec<Event>>,
    untracked: VecDeque<Event>,
    n_events: usize,
}

impl EventSorter {
    /// Creates a empty EventSorter.
    pub(crate) fn new() -> Self {
        EventSorter {
            series: BTreeMap::new(),
            untracked: VecDeque::new(),
            n_events: 0,
        }
    }

    /// Returns the total number of Events in the EventSorter.
    pub(crate) fn len(&self) -> usize {
        self.n_events
    }

    /// Adds an event to the EventSorter.
    pub(crate) fn add(&mut self, event: Event) {
        match event.get_section::<TrackingInfo>(ModuleId::Tracking) {
            Some(track) => match self.series.get_mut(track) {
                Some(series) => {
                    series.push(event);
                }
                None => {
                    self.series.insert(track.clone(), vec![event]);
                }
            },
            None => {
                warn!("Failed to sort event: no tracking information");
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
            if self.series.first_key_value().unwrap().0.skb.timestamp
                < self
                    .untracked
                    .get(0)
                    .unwrap()
                    .get_section::<CommonEvent>(ModuleId::Common)
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
        match self.series.pop_first() {
            Some((_, series)) => {
                self.n_events -= series.len();
                Some(series)
            }
            None => None,
        }
    }
}
