use anyhow::Result;

use super::bpf::*;
use crate::{
    core::events::{bpf::BpfRawSection, *},
    event_section, event_section_factory,
};

#[event_section]
pub(crate) struct OvsEvent {
    /// Shared by upcall, action, recv upcall, operation, upcall enqueue events.
    pub(crate) event_type: Option<String>,
    // Upcall data.
    pub(crate) upcall_port: Option<u32>,
    /// Upcall command. Holds OVS_PACKET_CMD:
    ///   OVS_PACKET_CMD_UNSPEC   = 0
    ///   OVS_PACKET_CMD_MISS     = 1
    ///   OVS_PACKET_CMD_ACTION   = 2
    ///   OVS_PACKET_CMD_EXECUTE  = 3
    pub(crate) cmd: Option<u8>,
    /// CPU id.
    pub(crate) cpu: Option<u32>,
    // Action event data.
    /// Action to be executed, values from enum ovs_action_attr (uapi/linux/openvswitch.h).
    pub(crate) action: Option<String>,
    pub(crate) recirculation_id: Option<u32>,
    // Action tracking data.
    pub(crate) queue_id: Option<u32>,
    // Output action data.
    pub(crate) port: Option<u32>,
    // Recv upcall data. Reuses "queue_id" from above.
    pub(crate) upcall_type: Option<u32>,
    pub(crate) pkt_size: Option<u32>,
    pub(crate) key_size: Option<u64>,
    pub(crate) batch_ts: Option<u64>,
    pub(crate) batch_idx: Option<u8>,
    // Operation data. Reuses "queue_id", "batch_ts" and "batch_idx" from above.
    /// Operation type, either "exec" or "put".
    pub(crate) op_type: Option<String>,
    // Upcall enqueue data. Reuses "cmd", "upcall_port", "queue_id" from above.
    pub(crate) r#return: Option<i32>,
    pub(crate) upcall_ts: Option<u64>,
    pub(crate) upcall_cpu: Option<u32>, // Shouldn't we reuse "cpu"?
    // Upcall return data. Reuses "upcall_ts", "upcall_cpu" from above.
    pub(crate) return_code: Option<i32>, // Shouldn't we reuse "r#return"?
}

#[derive(Default)]
#[event_section_factory(OvsEvent)]
pub(crate) struct OvsEventFactory {}

impl RawEventSectionFactory for OvsEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut event = OvsEvent::default();

        for section in raw_sections.iter() {
            match OvsEventType::from_u8(section.header.data_type)? {
                OvsEventType::Upcall => unmarshall_upcall(section, &mut event),
                OvsEventType::UpcallEnqueue => unmarshall_upcall_enqueue(section, &mut event),
                OvsEventType::UpcallReturn => unmarshall_upcall_return(section, &mut event),
                OvsEventType::RecvUpcall => unmarshall_recv(section, &mut event),
                OvsEventType::Operation => unmarshall_operation(section, &mut event),
                OvsEventType::ActionExec => unmarshall_exec(section, &mut event),
                OvsEventType::ActionExecTrack => unmarshall_exec_track(section, &mut event),
                OvsEventType::OutputAction => unmarshall_output(section, &mut event),
            }?;
        }

        Ok(Box::new(event))
    }
}
