//! Tracking processor.
//!
//! Events can be grouped in "series" of related events based on their tracking information
//! (skb-tracking and OvS queue_id). These series refer to the same packet.
//!
//! The tracking processor is a Processor keeps track of the events' tracking ids and
//! inserts a new EventSection with information that identifies each event with its series.

use std::{
    cmp::{Eq, PartialEq},
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, bail, Result};

use crate::events::*;

// Data identifying an OvsUpcall Event
#[derive(Debug, PartialEq, Eq, Hash)]
struct UpcallKey {
    /// Cpu of the upcall event
    cpu: u32,
    /// Timestamp of the upcall event
    ts: u64,
}

/// AddTracking is a helper that looks at the events' tracking information and inserts
/// information about the previous event of the same series.
pub(crate) struct AddTracking {
    /// Skb tracking map. Indexed by skb tracking id, this map used to access the TrackingInfo for
    /// each tracking id. Also, it allows us to "overwrite" the tracking information of certain
    /// events.
    skb_tracking: HashMap<u128, Arc<Mutex<TrackingInfo>>>,
    /// When an ovs queue_id is generated, its skb tracking info is stored in this map. The
    /// queue_id of future ovs events are looked up in this table to get the right tracking
    /// information.
    ovs_queue_tracking: HashMap<u32, Arc<Mutex<TrackingInfo>>>,
    /// When an upcall happens, the packet might get fragmented. This map is used to use the same
    /// TrackingInfo for all fragments.
    ovs_upcalls_tracking: HashMap<UpcallKey, Arc<Mutex<TrackingInfo>>>,
}

impl AddTracking {
    pub(crate) fn new() -> Self {
        AddTracking {
            skb_tracking: HashMap::new(),
            ovs_queue_tracking: HashMap::new(),
            ovs_upcalls_tracking: HashMap::new(),
        }
    }

    /// Process one event adding TrackingInfo section.
    pub(crate) fn process_one(&mut self, event: &mut Event) -> Result<()> {
        if let Some(ovs) = event.get_section::<OvsEvent>(SectionId::Ovs) {
            use OvsEvent::*;
            match ovs {
                Upcall { upcall } => {
                    let cpu = upcall.cpu;
                    // Lookup the skb-based tracking information.
                    let info = self.process_skb(event)?;

                    if let Some(info) = info {
                        // Store a reference to the TrackingInfo in upcall map. That way, it will be used
                        // for all nested enqueue events.
                        let ts = event
                            .get_section::<CommonEvent>(SectionId::Common)
                            .map(|c| c.timestamp)
                            .ok_or_else(|| anyhow!("malformed event: no common section"))?;
                        let key = UpcallKey { ts, cpu };

                        self.ovs_upcalls_tracking.insert(key, info);
                    }
                }
                UpcallReturn { upcall_return: ret } => {
                    // The upcall has finished. Remove the entry from the upcalls tracking table.
                    let key = UpcallKey {
                        ts: ret.upcall_ts,
                        cpu: ret.upcall_cpu,
                    };

                    // Lookup the skb-based tracking information.
                    self.process_skb(event)?;

                    self.ovs_upcalls_tracking.remove(&key);
                }
                UpcallEnqueue { upcall_enqueue } => {
                    // Get the tracking id from the in upcalls tracking table.
                    let upcall = UpcallKey {
                        ts: upcall_enqueue.upcall_ts,
                        cpu: upcall_enqueue.upcall_cpu,
                    };
                    let info = self
                        .ovs_upcalls_tracking
                        .get(&upcall)
                        .ok_or_else(|| anyhow!("Enqueue without an associated upcall event."))?;
                    info.lock().unwrap().idx += 1;

                    // Store a reference to the TrackingInfo in the ovs_queue tracking table.
                    self.ovs_queue_tracking
                        .insert(upcall_enqueue.queue_id, info.clone());

                    Self::insert_info(event, info)?;
                }
                RecvUpcall { recv_upcall } => {
                    let info = self.lookup_ovs_queue(recv_upcall.queue_id)?;
                    info.lock().unwrap().idx += 1;
                    Self::insert_info(event, &info)?;
                }
                Operation { flow_operation } => {
                    let info = self.lookup_ovs_queue(flow_operation.queue_id)?;
                    info.lock().unwrap().idx += 1;
                    Self::insert_info(event, &info)?;
                }
                Action { action_execute } => match action_execute.queue_id {
                    Some(queue_id) => {
                        // This action event came from an upcall. Restore the tracking id of the
                        // original packet.
                        let info = self.lookup_ovs_queue(queue_id)?;
                        info.lock().unwrap().idx += 1;

                        // Add an entry in the skb tracking table so that futre non-ovs events also
                        // get the tracking id from the original (upcalled) packet.
                        if let Some(skb) =
                            event.get_section::<SkbTrackingEvent>(SectionId::SkbTracking)
                        {
                            self.skb_tracking.insert(skb.tracking_id(), info.clone());
                        }

                        Self::insert_info(event, &info)?;
                    }
                    None => {
                        self.process_skb(event)?;
                    }
                },
                DpLookup {
                    flow_lookup: _lookup,
                } => todo!(),
            }
        } else {
            // It's not an OVS event, try skb-only tracking.
            self.process_skb(event)?;
        }
        Ok(())
    }

    // Insert TrackingInformation to an event.
    fn insert_info(event: &mut Event, info: &Arc<Mutex<TrackingInfo>>) -> Result<()> {
        let info = info.lock().unwrap().clone();
        if let Some(info_section) = event.get_section::<TrackingInfo>(SectionId::Tracking) {
            if *info_section != info {
                bail!("Event already has info section {info_section:?} and does not match computed {info:?}")
            }
        } else {
            event.insert_section(SectionId::Tracking, Box::new(info))?;
        }

        Ok(())
    }

    // Add tracking information to an event based on skb-tracking id if it exists.
    // Returns the TrackingInformation pointer if skb-tracking information was available.
    fn process_skb(&mut self, event: &mut Event) -> Result<Option<Arc<Mutex<TrackingInfo>>>> {
        if let Some(skb) = event.get_section::<SkbTrackingEvent>(SectionId::SkbTracking) {
            let tracking_id = skb.tracking_id();
            let info = match self.skb_tracking.get(&tracking_id) {
                Some(info) => {
                    let mut locked_info = info.lock().unwrap();
                    locked_info.idx += 1;
                    info.clone()
                }
                None => {
                    // First time we see this skb. Add it to global table.
                    let info = Arc::new(Mutex::new(TrackingInfo::new(skb)?));
                    self.skb_tracking.insert(tracking_id, info.clone());
                    info
                }
            };
            Self::insert_info(event, &info)?;
            Ok(Some(info))
        } else {
            Ok(None)
        }
    }

    // Lookup tracking information by ovs queue id.
    fn lookup_ovs_queue(&mut self, queue_id: u32) -> Result<Arc<Mutex<TrackingInfo>>> {
        Ok(self
            .ovs_queue_tracking
            .get(&queue_id)
            .ok_or_else(|| anyhow!("Queue Id lookup failed for OVS userspace event: {queue_id}",))?
            .clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};
    use serde_json::Value;

    static EVENTS: [(&str, TrackingInfo); 1] = [
        // Upcall event
        (
            r#"{"idx":9,"skb":{"orig_head":18446616575029637120,"skb":18446616575340381184,"timestamp":689436955471671}}"#,
            TrackingInfo {
                skb: SkbTrackingEvent {
                    orig_head: 18446616575029637120,
                    timestamp: 689436955471671,
                    skb: 18446616575340381184,
                },
                idx: 9,
            },
        ),
    ];

    #[test]
    fn test_event_to_json() -> Result<()> {
        for (event_json, event) in EVENTS.iter() {
            let json = serde_json::to_string(event)
                .map_err(|e| anyhow!("Failed to convert event {event:?} to json: {e}"))?;
            // Comparing json strings is error prone. Convert them to Values and compare those.
            assert_eq!(
                serde_json::from_str::<Value>(json.as_str()).unwrap(),
                serde_json::from_str::<Value>(event_json).unwrap()
            );
        }
        Ok(())
    }

    #[test]
    fn test_json_to_event() -> Result<()> {
        for (event_json, event) in EVENTS.iter() {
            let parsed: TrackingInfo = serde_json::from_str(event_json)
                .map_err(|e| anyhow!("Failed to convert json '{event_json}' to event: {e}"))?;
            assert_eq!(&parsed, event);
        }
        Ok(())
    }
}
