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

const MAX_REQUESTS_PER_SEC: u64 = 10;
const MAX_FLOW_AGE_SECS: u64 = 5;

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
    // Factory to use for event creation
    events_factory: Arc<RetisEventsFactory>,
    // Thread handle
    thread: Option<thread::JoinHandle<()>>,
    // Whether ofproto/detrace is supported
    detrace_supported: bool,

    // Sender and receiver of the channel that is used to request enrichments
    sender: mpsc::Sender<EnrichRequest>,
    receiver: Option<mpsc::Receiver<EnrichRequest>>,
}

impl FlowEnricher {
    pub(crate) fn new(events_factory: Arc<RetisEventsFactory>) -> Result<Self> {
        let (sender, receiver) = mpsc::channel::<EnrichRequest>();

        let mut unixctl = OvsUnixCtl::new(Some(Duration::from_millis(500)))?;
        let commands = unixctl
            .list_commands()
            .map_err(|e| anyhow!("cannot connect OVS: {e}"))?;

        Ok(FlowEnricher {
            events_factory,
            thread: None,
            sender,
            receiver: Some(receiver),
            detrace_supported: commands.iter().any(|(c, _)| c == "ofproto/detrace"),
        })
    }

    pub(crate) fn detrace_supported(&self) -> bool {
        self.detrace_supported
    }

    pub(crate) fn sender(&self) -> &mpsc::Sender<EnrichRequest> {
        &self.sender
    }

    pub(crate) fn start(&mut self, state: Running) -> Result<()> {
        let detrace_supported = self.detrace_supported;
        let factory = self.events_factory.clone();
        let receiver = self
            .receiver
            .take()
            .ok_or_else(|| anyhow!("ovs-flow-enricher: ufid receiver not available"))?;

        let mut unixctl = OvsUnixCtl::new(Some(Duration::from_millis(500)))?;
        self.thread = Some(
            thread::Builder::new()
                .name("ovs-flow-enricher".into())
                .spawn(move || {
                    let mut tasks: VecDeque<EnrichRequest> = VecDeque::new();
                    let mut next_request = SystemTime::UNIX_EPOCH;
                    let mut wait_time = Duration::from_millis(500);
                    let mut registry = FlowInfoRegistry::default();

                    let min_request_time = Duration::from_millis(1000 / MAX_REQUESTS_PER_SEC);
                    let flow_age_time = Duration::from_secs(MAX_FLOW_AGE_SECS);

                    let mut failed_requests: u64 = 0;

                    while state.running() {
                        use mpsc::RecvTimeoutError::*;
                        let req = match receiver.recv_timeout(wait_time) {
                            Ok(req) => Some(req),
                            Err(Disconnected) => break,
                            Err(Timeout) => None,
                        };

                        let now = SystemTime::now();

                        // Garbage-collect registry.
                        registry.run(&(now - flow_age_time));

                        if let Some(req) = req {
                            // Remove any pending tasks with the same ufid.
                            tasks.retain(|t| t.ufid != req.ufid);
                            // Drop requests that have already been processed.
                            if !registry.lookup(&req) {
                                tasks.push_back(req);
                            }
                        }

                        // Nothing to do.
                        if tasks.is_empty() {
                            wait_time = Duration::from_millis(500);
                            continue;
                        }

                        // Too soon for another request.
                        if now < next_request {
                            wait_time = next_request.duration_since(now).unwrap();
                            debug!(
                                "ovs-flow-enricher: Delaying requests to OVS for another {} ms. Pending tasks {}",
                                wait_time.as_millis(),
                                tasks.len(),
                            );
                            continue;
                        }
                        next_request = now + min_request_time;

                        // Timestamp of the first request that is worth enriching.
                        let front_time = now - flow_age_time;
                        let front_pos = tasks
                            .iter()
                            .position(|r| r.ts >= front_time)
                            .unwrap_or(tasks.len() - 1);
                        if front_pos > 0 {
                            warn!(
                                "ovs-flow-enricher: Deleting {front_pos} old enrichment requests"
                            );
                            tasks.drain(0..front_pos);
                        }

                        let task = tasks.pop_front();
                        if task.is_none() {
                            continue;
                        }
                        let task = task.unwrap();

                        let ufid_str = format!("ufid:{}", &task.ufid);
                        debug!(
                            "ovs-flow-enricher: Enriching flow. Pending enrichment tasks {}",
                            tasks.len()
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
                                .run("ofproto/detrace", Some(&[ufid_str.as_str(), "pmd=2147483647"]))
                            {
                                Err(e) => {
                                    error!("ovs-flow-enricher: failed to detrace flow {e}");
                                    continue;
                                }
                                Ok(None) => {
                                    // If the datapath flow was removed before enrichment this
                                    // could happen.
                                    warn!("ovs-flow-enricher: ofproto/detrace returned empty data");
                                    continue;
                                }
                                Ok(Some(data)) => {
                                    if data.is_empty() || data.starts_with("Cache was not found") {
                                        debug!(
                                            "ovs-flow-enricher: Openflow cache missed, retrying later"
                                        );
                                        tasks.push_front(task);
                                        continue;
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

                        if let Err(e) = factory.add_event(fill_event(flow_info.clone())) {
                            error!("ovs-flow-enricher failed to add event {e:?}");
                        }

                        registry.insert(task, flow_info);
                    }

                    if failed_requests > 0 {
                        warn!("ovs-flow-enricher: {failed_requests} requests failed");
                    }
                    if !tasks.is_empty() {
                        info!("ovs-flow-enricher: {} unsent requests", tasks.len());
                    }
                })?,
        );
        Ok(())
    }

    pub(crate) fn join(&mut self) -> Result<()> {
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|e| anyhow!("Failed to join othread ovs-flow-enricher: {e:?}"))
        } else {
            Ok(())
        }
    }
}

fn fill_event(info: OvsFlowInfoEvent) -> impl Fn(&mut Event) -> Result<()> {
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

// The FlowInfoRegistry keeps track of what events have already been generated.
//
// It is supposed to work within the FlowEnricher thread who should periodically call run()
// function to execute evictions.
#[derive(Default)]
struct FlowInfoRegistry {
    data: HashMap<Ufid, FlowInfoRecord>,
}

impl FlowInfoRegistry {
    // Lookup EnrichRequest in registry
    fn lookup(&mut self, request: &EnrichRequest) -> bool {
        let mut flow_changed = false;
        if let Some(r) = self.data.get_mut(&request.ufid) {
            if r.event.flow == request.flow && r.event.sf_acts == request.sf_acts {
                // It's definitely the same flow
                r.last_used = SystemTime::now();
            } else {
                // Same UFID different flow and acts pointer. The flow must have changed
                // keeping the same key. Delete the old entry.
                flow_changed = true;
            }
        } else {
            return false;
        }
        if flow_changed {
            self.data.remove(&request.ufid);
            false
        } else {
            true
        }
    }

    fn insert(&mut self, request: EnrichRequest, event: OvsFlowInfoEvent) {
        self.data.insert(
            request.ufid,
            FlowInfoRecord {
                event,
                last_used: request.ts,
            },
        );
    }

    fn run(&mut self, threshold: &SystemTime) {
        self.data.retain(|_, r| &r.last_used > threshold);
    }
}
