use anyhow::{bail, Result};
use plain::Plain;
use serde::{
    de::Error as Derror, ser::Error as Serror, Deserialize, Deserializer, Serialize, Serializer,
};

use super::bpf::*;
use crate::{
    core::events::{bpf::BpfRawSection, *},
    event_section, event_section_factory,
};

///The OVS Event
#[derive(Debug, PartialEq)]
#[event_section]
pub(crate) struct OvsEvent {
    /// Event data
    #[serde(flatten)]
    pub(crate) event: OvsEventType,
}

#[derive(Default)]
#[event_section_factory(OvsEvent)]
pub(crate) struct OvsEventFactory {}

impl RawEventSectionFactory for OvsEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut event = OvsEvent::default();

        for section in raw_sections.iter() {
            match OvsDataType::from_u8(section.header.data_type)? {
                OvsDataType::Upcall => unmarshall_upcall(section, &mut event),
                OvsDataType::UpcallEnqueue => unmarshall_upcall_enqueue(section, &mut event),
                OvsDataType::UpcallReturn => unmarshall_upcall_return(section, &mut event),
                OvsDataType::RecvUpcall => unmarshall_recv(section, &mut event),
                OvsDataType::Operation => unmarshall_operation(section, &mut event),
                OvsDataType::ActionExec => unmarshall_exec(section, &mut event),
                OvsDataType::ActionExecTrack => unmarshall_exec_track(section, &mut event),
                OvsDataType::OutputAction => unmarshall_output(section, &mut event),
            }?;
        }

        Ok(Box::new(event))
    }
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
#[serde(tag = "event_type")]
pub(crate) enum OvsEventType {
    /// Upcall event. It indicates the begining of an upcall. An upcall can have multiple enqueue
    /// events.
    #[serde(rename = "upcall")]
    Upcall(UpcallEvent),

    /// Upcall enqueue event. It indicates a packet (fragment) is enqueued for userspace
    /// processing.
    #[serde(rename = "upcall_enqueue")]
    UpcallEnqueue(UpcallEnqueueEvent),

    /// Upcall return event. It indicates an upcall has ended.
    #[serde(rename = "upcall_return")]
    UpcallReturn(UpcallReturnEvent),

    /// Receive upcall event. It indicates userspace has received an upcall.
    #[serde(rename = "recv_upcall")]
    RecvUpcall(RecvUpcallEvent),

    /// Operation event. It indicates userspace has executed a flow operation on an upcalled
    /// packet.
    #[serde(rename = "flow_operation")]
    Operation(OperationEvent),

    /// Action execution event. It indicates the datapath has executed an action on a packet.
    #[serde(rename = "action_execute")]
    Action(ActionEvent),

    #[serde(rename = "undefined")]
    #[default]
    Undefined,
}

// This struct is also used for ebpf decoding.
// Please keep it sync with its ebpf counterpart in
// "bpf/kernel_upcall_tp.bpf.c".
/// OVS upcall event
#[derive(Debug, PartialEq, Copy, Clone, Default, Deserialize, Serialize)]
#[repr(C)]
pub(crate) struct UpcallEvent {
    /// Upcall command. Holds OVS_PACKET_CMD:
    ///   OVS_PACKET_CMD_UNSPEC   = 0
    ///   OVS_PACKET_CMD_MISS     = 1
    ///   OVS_PACKET_CMD_ACTION   = 2
    ///   OVS_PACKET_CMD_EXECUTE  = 3
    pub(crate) cmd: u8,
    /// Upcall port.
    pub(crate) port: u32,
    /// Cpu ID
    pub(crate) cpu: u32,
}
unsafe impl Plain for UpcallEvent {}

// This struct is also used for ebpf decoding.
// Please keep it sync with its ebpf counterpart in
// "bpf/kernel_enqueue.bpf.c".
/// Upcall enqueue event.
#[derive(Debug, PartialEq, Copy, Clone, Default, Deserialize, Serialize)]
#[repr(C)]
pub(crate) struct UpcallEnqueueEvent {
    /// Return code. Any value different from zero indicates the upcall enqueue
    /// failed probably indicating a packet drop.
    pub(crate) ret: i32,
    /// Upcall command executed.
    pub(crate) cmd: u8,
    /// Upcall port id.
    pub(crate) port: u32,
    /// Timestamp of the associated UpcallEvent.
    pub(crate) upcall_ts: u64,
    /// CPU id of the associated UpcallEvent.
    pub(crate) upcall_cpu: u32,
    /// Enqueue id used for tracking.
    pub(crate) queue_id: u32,
}
unsafe impl Plain for UpcallEnqueueEvent {}

// This struct is also used for ebpf decoding.
// Please keep it sync with its ebpf counterpart in
// "bpf/kernel_upcall_ret.bpf.c".
/// Upcall return event
#[derive(Debug, PartialEq, Copy, Clone, Default, Deserialize, Serialize)]
#[repr(C)]
pub(crate) struct UpcallReturnEvent {
    pub(crate) upcall_ts: u64,
    pub(crate) upcall_cpu: u32,
    pub(crate) ret: i32,
}
unsafe impl Plain for UpcallReturnEvent {}

// This struct is also used for ebpf decoding.
// Please keep it sync with its ebpf counterpart in
// "bpf/include/ovs_operation.h".
/// Operation event.
#[derive(Debug, PartialEq, Copy, Clone, Default, Deserialize, Serialize)]
#[repr(C)]
pub(crate) struct OperationEvent {
    /// Operation type ("put" or "exec")
    #[serde(
        deserialize_with = "OperationEvent::deserialize_op",
        serialize_with = "OperationEvent::serialize_op"
    )]
    pub(crate) op_type: u8,
    /// Queue id used for tracking
    pub(crate) queue_id: u32,
    /// Timestamp of the begining of batch
    pub(crate) batch_ts: u64,
    /// Index within the batch
    pub(crate) batch_idx: u8,
}
unsafe impl Plain for OperationEvent {}

impl OperationEvent {
    fn operation_str(op_type: u8) -> Result<&'static str> {
        Ok(match op_type {
            0 => "exec",
            1 => "put",
            x => bail!("Unknown operation type {x}"),
        })
    }

    fn deserialize_op<'de, D>(deserializer: D) -> Result<u8, D::Error>
    where
        D: Deserializer<'de>,
    {
        let st = String::deserialize(deserializer)?;
        match st.as_str() {
            "exec" => Ok(0),
            "put" => Ok(1),
            other => Err(D::Error::custom(format!(
                "Unknown operation string {other}"
            ))),
        }
    }

    fn serialize_op<S>(op_type: &u8, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(OperationEvent::operation_str(*op_type).map_err(S::Error::custom)?)
    }
}

// This struct is also used for ebpf decoding.
// Please keep it sync with its ebpf counterpart in
// "bpf/user_recv_upcall.bpf.c".
/// OVS Receive Event
#[derive(Debug, PartialEq, Copy, Clone, Default, Deserialize, Serialize)]
#[repr(C)]
pub(crate) struct RecvUpcallEvent {
    /// Type of upcall
    pub(crate) r#type: u32,
    /// Packet size
    pub(crate) pkt_size: u32,
    /// Key size
    pub(crate) key_size: u64,
    /// Queue id used for tracking
    pub(crate) queue_id: u32,
    /// Timestamp of the begining of batch
    pub(crate) batch_ts: u64,
    /// Index within the batch
    pub(crate) batch_idx: u8,
}
unsafe impl Plain for RecvUpcallEvent {}

/// OVS output action data.
#[derive(Debug, PartialEq, Copy, Clone, Default, Deserialize, Serialize)]
pub(crate) struct ActionEvent {
    /// Action to be executed.
    #[serde(flatten)]
    pub(crate) action: OvsAction,
    /// Recirculation id.
    pub(crate) recirc_id: u32,
    /// Queue id used for tracking. None if not tracking or if the output event did not come from
    /// an upcall.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) queue_id: Option<u32>,
}

#[derive(Debug, PartialEq, Copy, Clone, Default, Deserialize, Serialize)]
#[serde(tag = "action")]
pub(crate) enum OvsAction {
    #[serde(rename = "unspecified")]
    #[default]
    Unspecified,
    #[serde(rename = "output")]
    Output(OvsActionOutput),
    #[serde(rename = "userspace")]
    Userspace,
    #[serde(rename = "set")]
    Set,
    #[serde(rename = "push_vlan")]
    PushVlan,
    #[serde(rename = "pop_vlan")]
    PopVlan,
    #[serde(rename = "sample")]
    Sample,
    #[serde(rename = "recirc")]
    Recirc,
    #[serde(rename = "hash")]
    Hash,
    #[serde(rename = "push_mpls")]
    PushMpls,
    #[serde(rename = "pop_mpls")]
    PopMpls,
    #[serde(rename = "set_masked")]
    SetMasked,
    #[serde(rename = "ct")]
    Ct,
    #[serde(rename = "trunc")]
    Trunc,
    #[serde(rename = "push_eth")]
    PushEth,
    #[serde(rename = "pop_eth")]
    PopEth,
    #[serde(rename = "ct_clear")]
    CtClear,
    #[serde(rename = "push_nsh")]
    PushNsh,
    #[serde(rename = "pop_nsh")]
    PopNsh,
    #[serde(rename = "meter")]
    Meter,
    #[serde(rename = "clone")]
    Clone,
    #[serde(rename = "check_pkt_len")]
    CheckPktLen,
    #[serde(rename = "add_mpls")]
    AddMpls,
    #[serde(rename = "dec_ttl")]
    DecTtl,
}

/// OVS output action data.
#[derive(Debug, PartialEq, Copy, Clone, Default, Deserialize, Serialize)]
pub(crate) struct OvsActionOutput {
    /// Output port.
    pub(crate) port: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};
    use serde_json::Value;

    static EVENTS: [(&'static str, OvsEvent); 6] = [
        // Upcall event
        (
            r#"{"cmd":1,"cpu":0,"event_type":"upcall","port":4195744766}"#,
            OvsEvent {
                event: OvsEventType::Upcall(UpcallEvent {
                    cmd: 1,
                    cpu: 0,
                    port: 4195744766,
                }),
            },
        ),
        // Action event
        (
            r#"{"action":"output","event_type":"action_execute","port":2,"queue_id":1361394472,"recirc_id":0}"#,
            OvsEvent {
                event: OvsEventType::Action(ActionEvent {
                    action: OvsAction::Output(OvsActionOutput { port: 2 }),
                    recirc_id: 0,
                    queue_id: Some(1361394472),
                }),
            },
        ),
        // Upcall enqueue event
        (
            r#"{"cmd":1,"event_type":"upcall_enqueue","queue_id":3316322986,"ret":0,"upcall_cpu":0,"port":4195744766,"upcall_ts":61096236973661}"#,
            OvsEvent {
                event: OvsEventType::UpcallEnqueue(UpcallEnqueueEvent {
                    ret: 0,
                    cmd: 1,
                    port: 4195744766,
                    upcall_ts: 61096236973661,
                    upcall_cpu: 0,
                    queue_id: 3316322986,
                }),
            },
        ),
        // Upcall return event
        (
            r#"{"event_type":"upcall_return","ret":0,"upcall_cpu":0,"upcall_ts":61096236973661}"#,
            OvsEvent {
                event: OvsEventType::UpcallReturn(UpcallReturnEvent {
                    ret: 0,
                    upcall_ts: 61096236973661,
                    upcall_cpu: 0,
                }),
            },
        ),
        // Operation event exec
        (
            r#"{"batch_idx":0,"batch_ts":61096237019698,"event_type":"flow_operation","op_type":"exec","queue_id":3316322986}"#,
            OvsEvent {
                event: OvsEventType::Operation(OperationEvent {
                    op_type: 0,
                    queue_id: 3316322986,
                    batch_ts: 61096237019698,
                    batch_idx: 0,
                }),
            },
        ),
        // Operation event put
        (
            r#"{"batch_idx":0,"batch_ts":61096237019698,"event_type":"flow_operation","op_type":"put","queue_id":3316322986}"#,
            OvsEvent {
                event: OvsEventType::Operation(OperationEvent {
                    op_type: 1,
                    queue_id: 3316322986,
                    batch_ts: 61096237019698,
                    batch_idx: 0,
                }),
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
                serde_json::from_str::<Value>(*event_json).unwrap()
            );
        }
        Ok(())
    }

    #[test]
    fn test_json_to_event() -> Result<()> {
        for (event_json, event) in EVENTS.iter() {
            let parsed: OvsEvent = serde_json::from_str(*event_json)
                .map_err(|e| anyhow!("Failed to convert json '{event_json}' to event: {e}"))?;
            assert_eq!(&parsed, event);
        }
        Ok(())
    }
}
