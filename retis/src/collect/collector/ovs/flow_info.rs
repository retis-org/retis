//! OpenvSwitch flow information enrichment.
//!
//! The OpenvSwitch datapath is made of flows which are comprised of
//! a match and a list actions. They are uniquely identified by a unique
//! flow id, or UFID.
//!
//! Each of these datapath flows are built as a result of the OpenFlow rule
//! classification which typically involves many OpenFlow rules. Therefore,
//! each datapath flow is the result of several OpenFlow rules being matched.
//!
//! OpenvSwitch 3.4 supports extracting the OpenFlow rules that contributed to
//! the creation of each datapath flow through a unixctl command called
//! "ofproto/detrace".
//!
//! This module implements a thread that can query OpenvSwitch for this information
//! (caching the results) and enrich the event file with this relationship.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use ovs_unixctl::OvsUnixCtl;

use crate::core::events::factory::RetisEventsFactory;
use crate::events::*;
use crate::helpers::signals::Running;

const MAX_FLOW_AGE_SECS: u64 = 10;
const CHANNEL_SIZE: usize = 100;
const DEFAULT_TIMEOUT_MS: u64 = 500;
const PMD_ID_NULL: i32 = i32::MAX;

// A request to enrich a flow
pub(crate) struct EnrichRequest {
    ufid: Ufid,
    flow: u64,
    sf_acts: u64,
    ts: SystemTime,
}

impl EnrichRequest {
    pub(crate) fn new(ufid: Ufid, flow: u64, sf_acts: u64) -> Self {
        EnrichRequest {
            ufid,
            flow,
            sf_acts,
            ts: SystemTime::now(),
        }
    }
}

pub(crate) struct FlowEnricher {
    // The unixctl handler
    unixctl: Option<OvsUnixCtl>,
    // Factory to use for event creation
    events_factory: Arc<RetisEventsFactory>,
    // Thread handle
    thread: Option<thread::JoinHandle<()>>,
    // Whether ofproto/detrace is supported
    detrace_supported: bool,
    // Rate of requests
    rate: u32,

    // Sender and receiver of the channel that is used to request enrichments
    sender: mpsc::SyncSender<EnrichRequest>,
    receiver: Option<mpsc::Receiver<EnrichRequest>>,
}

impl FlowEnricher {
    pub(crate) fn new(events_factory: Arc<RetisEventsFactory>, rate: u32) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<EnrichRequest>(CHANNEL_SIZE);

        let mut unixctl = OvsUnixCtl::new(Some(Duration::from_millis(500)))?;
        let detrace_supported = unixctl
            .list_commands()
            .map_err(|e| anyhow!("cannot connect to ovs-vswitchd control interface: {e}"))?
            .iter()
            .any(|(c, _)| c == "ofproto/detrace");

        if !detrace_supported {
            debug!("ovs-flow-enricher: ovs-vswitchd does not support ofproto/detrace");
        }

        Ok(FlowEnricher {
            unixctl: Some(unixctl),
            events_factory,
            thread: None,
            sender,
            receiver: Some(receiver),
            detrace_supported,
            rate,
        })
    }

    pub(crate) fn detrace_supported(&self) -> bool {
        self.detrace_supported
    }

    pub(crate) fn sender(&self) -> &mpsc::SyncSender<EnrichRequest> {
        &self.sender
    }

    pub(crate) fn start(&mut self, state: Running) -> Result<()> {
        let detrace_supported = self.detrace_supported;
        let factory = self.events_factory.clone();
        let receiver = self
            .receiver
            .take()
            .ok_or_else(|| anyhow!("ovs-flow-enricher: ufid receiver not available"))?;
        let mut unixctl = self
            .unixctl
            .take()
            .ok_or_else(|| anyhow!("ovs-flow-enricher: unixctl not found"))?;

        let min_request_time = Duration::from_millis((1000 / self.rate).into());

        self.thread = Some(
            thread::Builder::new()
                .name("ovs-flow-enricher".into())
                .spawn(move || {
                    let mut next_request = SystemTime::UNIX_EPOCH;
                    let mut wait_time = Duration::from_millis(DEFAULT_TIMEOUT_MS);
                    let mut registry = FlowInfoRegistry::default();


                    let mut failed_requests: u64 = 0;

                    while state.running() {
                        use mpsc::RecvTimeoutError::*;
                        let req = match receiver.recv_timeout(wait_time) {
                            Ok(req) => Some(req),
                            Err(Disconnected) => break,
                            Err(Timeout) => None,
                        };

                        registry.expire();

                        if let Some(req) = req {
                            registry.queue_add(req);
                        }

                        // Nothing to do.
                        if registry.queue_is_empty() {
                            wait_time = Duration::from_millis(DEFAULT_TIMEOUT_MS);
                            continue;
                        }

                        // Rate-limit requests.
                        let now = SystemTime::now();
                        if now < next_request {
                            wait_time = next_request.duration_since(now).unwrap();
                            debug!(
                                "ovs-flow-enricher: Delaying requests to OVS for another {} ms. Pending tasks {}",
                                wait_time.as_millis(),
                                registry.queue_len(),
                            );
                            continue;
                        }
                        next_request = now + min_request_time;

                        // Get the next request from the queue and process it.
                        let task = match registry.queue_next() {
                            None => continue,
                            Some(task) => task,
                        };

                        let ufid_str = format!("ufid:{}", &task.ufid);
                        debug!(
                            "ovs-flow-enricher: Enriching flow {ufid_str}. Pending enrichment tasks {}",
                            registry.queue_len()
                        );

                        let dpflow = match unixctl.run("dpctl/get-flow", Some(&[ufid_str.as_str()])) {
                            Err(e) => {
                                // If the datapath flow was removed before enrichment or OVS runs
                                // in a namespace, this could happen.
                                debug!("ovs-flow-enricher: failed to get flow {e}");
                                failed_requests += 1;
                                continue;
                            }
                            Ok(None) => {
                                // If the datapath flow was removed before enrichment or OVS runs
                                // in a namespace, this could happen.
                                failed_requests += 1;
                                continue;
                            }
                            Ok(Some(data)) => String::from(data.trim()),
                        };

                        let ofpflows = if detrace_supported {
                            match unixctl
                                .run("ofproto/detrace", Some(&[ufid_str.as_str(), format!("pmd={}", PMD_ID_NULL).as_str()]))
                            {
                                Err(e) => {
                                    error!("ovs-flow-enricher: failed to detrace flow {e}");
                                    failed_requests += 1;
                                    continue;
                                }
                                Ok(None) => {
                                    // If the datapath flow was removed before enrichment this
                                    // could happen.
                                    warn!("ovs-flow-enricher: ofproto/detrace returned empty data");
                                    failed_requests += 1;
                                    continue;
                                }
                                Ok(Some(data)) => {
                                    if data.is_empty() || data.starts_with("Cache was not found") {
                                        debug!(
                                            "ovs-flow-enricher: Openflow cache missed, retrying later"
                                        );
                                        registry.queue_reinsert(task); continue;
                                    }
                                    data.lines().map(String::from).collect()
                                }
                            }
                        } else {
                            Vec::new()
                        };

                        let flow_info = OvsFlowInfoEvent {
                            ufid: task.ufid,
                            flow: task.flow,
                            sf_acts: task.sf_acts,
                            dpflow,
                            ofpflows,
                        };

                        if let Err(e) = factory.add_event(fill_event(&flow_info)) {
                            error!("ovs-flow-enricher failed to add event {e:?}");
                        }

                        registry.cache_insert(task, flow_info);
                    }

                    if failed_requests > 0 {
                        warn!("ovs-flow-enricher: {failed_requests} requests failed");
                    }
                    if !registry.queue_is_empty() {
                        info!("ovs-flow-enricher: {} unsent requests", registry.queue_len());
                    }
                })?,
        );
        Ok(())
    }

    pub(crate) fn join(&mut self) -> Result<()> {
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|e| anyhow!("Failed to join thread ovs-flow-enricher: {e:?}"))
        } else {
            Ok(())
        }
    }
}

fn fill_event(info: &'_ OvsFlowInfoEvent) -> impl Fn(&mut Event) -> Result<()> + use<'_> {
    move |event| -> Result<()> {
        event.insert_section(SectionId::OvsFlowInfo, Box::new(info.clone()))
    }
}

// Entries of the FlowInfoRegistry
#[derive(Clone)]
struct FlowInfoRecord {
    event: OvsFlowInfoEvent,
    last_used: SystemTime,
}

// The FlowInfoRegistry keeps track of events that are waiting to be enriched and which ones have
// already been enriched. It acts both as a cache and as a queue.
#[derive(Default)]
struct FlowInfoRegistry {
    cache: HashMap<Ufid, FlowInfoRecord>,
    queue: VecDeque<EnrichRequest>,
}

impl FlowInfoRegistry {
    const FLOW_AGE_TIME: Duration = Duration::from_secs(MAX_FLOW_AGE_SECS);

    fn queue_is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn queue_len(&self) -> usize {
        self.queue.len()
    }

    // Reinsert a request that was dequeued but that needs to be re-processed later on.
    fn queue_reinsert(&mut self, req: EnrichRequest) {
        self.queue.push_front(req)
    }

    // Add a request to the queue
    fn queue_add(&mut self, req: EnrichRequest) {
        // Do not add cached requests.
        if self.cache_lookup(&req) {
            return;
        }
        // Remove any pending tasks with the same ufid.
        self.queue.retain(|t| t.ufid != req.ufid);
        self.queue.push_back(req);
    }

    // Returns the next request that needs to be processed.
    fn queue_next(&mut self) -> Option<EnrichRequest> {
        self.queue.pop_front()
    }

    // Lookup an EnrichRequest in the cache returning whether an equivalent entry was found.
    // If an entry is found, the `last_used` field is updated.
    fn cache_lookup(&mut self, request: &EnrichRequest) -> bool {
        match self.cache.get_mut(&request.ufid) {
            Some(r) => {
                if r.event.flow == request.flow && r.event.sf_acts == request.sf_acts {
                    // It's definitely the same flow.
                    r.last_used = SystemTime::now();
                    true
                } else {
                    // Same UFID different flow and acts pointer. The flow must have changed
                    // keeping the same key. Delete the old entry.
                    self.cache.remove(&request.ufid);
                    false
                }
            }
            None => false,
        }
    }

    fn cache_insert(&mut self, request: EnrichRequest, event: OvsFlowInfoEvent) {
        self.cache.insert(
            request.ufid,
            FlowInfoRecord {
                event,
                last_used: request.ts,
            },
        );
    }

    // OVS keeps idle flows for `FLOW_AGE_TIME` seconds before removing them
    // from the datapath (and removing all internal information about them).
    // Expire both pending requests and idle cache entries that are older than
    // that to safe space and avoid sending requests for deleted flows.
    fn expire(&mut self) {
        let threshold = SystemTime::now() - FlowInfoRegistry::FLOW_AGE_TIME;

        self.cache.retain(|_, r| r.last_used > threshold);

        if !self.queue.is_empty() {
            let front_pos = self
                .queue
                .iter()
                .position(|r| r.ts >= threshold)
                .unwrap_or(self.queue.len() - 1);
            if front_pos > 0 {
                warn!("ovs-flow-enricher: Deleting {front_pos} old enrichment requests");
                self.queue.drain(0..front_pos);
            }
        }
    }
}
