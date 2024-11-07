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

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use log::error;

use crate::core::events::factory::RetisEventsFactory;
use crate::events::*;
use crate::helpers::signals::Running;

pub(crate) struct FlowEnricher {
    // Factory to use for event creation
    events_factory: Arc<RetisEventsFactory>,
    // Thread handle
    thread: Option<thread::JoinHandle<()>>,

    // Sender and receiver of the channel that is used to request enrichments
    sender: mpsc::Sender<Ufid>,
    receiver: Option<mpsc::Receiver<Ufid>>,
}

impl FlowEnricher {
    pub(crate) fn new(events_factory: Arc<RetisEventsFactory>) -> Self {
        let (sender, receiver) = mpsc::channel::<Ufid>();
        FlowEnricher {
            events_factory,
            thread: None,
            sender,
            receiver: Some(receiver),
        }
    }

    pub(crate) fn sender(&self) -> &mpsc::Sender<Ufid> {
        &self.sender
    }

    pub(crate) fn start(&mut self, state: Running) -> Result<()> {
        let factory = self.events_factory.clone();
        let receiver = self
            .receiver
            .take()
            .ok_or_else(|| anyhow!("ovs-flow-enricher: ufid receiver not available"))?;

        self.thread = Some(
            thread::Builder::new()
                .name("ovs-flow-enricher".into())
                .spawn(move || {
                    while state.running() {
                        match receiver.recv_timeout(Duration::from_millis(500)) {
                            Ok(ufid) => {
                                let dpflow = format!("{}", ufid);
                                let ofpflows = vec!["ofp1".into(), "ofp2".into()];

                                if let Err(e) =
                                    factory.add_event(fill_event(ufid, dpflow, ofpflows))
                                {
                                    error!("ovs-flow-enricher: failed to add event {e}");
                                }
                            }
                            Err(_) => (),
                        }
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

fn fill_event(
    ufid: Ufid,
    dpflow: String,
    ofpflows: Vec<String>,
) -> impl Fn(&mut Event) -> Result<()> {
    move |event| -> Result<()> {
        event.insert_section(
            SectionId::OvsFlowInfo,
            Box::new(OvsFlowInfoEvent {
                ufid,
                dpflow: dpflow.clone(),
                ofpflows: ofpflows.clone(),
            }),
        )
    }
}
