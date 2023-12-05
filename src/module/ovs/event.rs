use std::fmt;

use anyhow::{bail, Result};
use serde::{de::Error as Derror, ser::Error as Serror, Deserialize, Deserializer, Serializer};

use super::bpf::*;
use crate::{
    core::events::{bpf::BpfRawSection, *},
    event_section, event_section_factory, event_type, event_type_no_py,
};

///The OVS Event
#[derive(PartialEq)]
#[event_section]
pub(crate) struct OvsEvent {
    /// Event data
    #[serde(flatten)]
    pub(crate) event: OvsEventType,
}

impl EventFmt for OvsEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, format: DisplayFormat) -> fmt::Result {
        self.event.event_fmt(f, format)
    }
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
                OvsDataType::RecircAction => unmarshall_recirc(section, &mut event),
                OvsDataType::ConntrackAction => unmarshall_ct(section, &mut event),
            }?;
        }

        Ok(Box::new(event))
    }
}

#[event_type_no_py]
#[serde(tag = "event_type")]
#[derive(Default, PartialEq)]
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

impl EventFmt for OvsEventType {
    fn event_fmt(&self, f: &mut fmt::Formatter, format: DisplayFormat) -> fmt::Result {
        use OvsEventType::*;
        let disp: &dyn EventFmt = match self {
            Upcall(e) => e,
            UpcallEnqueue(e) => e,
            UpcallReturn(e) => e,
            RecvUpcall(e) => e,
            Operation(e) => e,
            Action(e) => e,
            Undefined => return write!(f, "?"),
        };

        disp.event_fmt(f, format)
    }
}

fn fmt_upcall_cmd(cmd: u8) -> &'static str {
    match cmd {
        0 => " (unspec)",
        1 => " (miss)",
        2 => " (action)",
        3 => " (exec)",
        _ => "",
    }
}

// This struct is also used for ebpf decoding.
// Please keep it sync with its ebpf counterpart in
// "bpf/kernel_upcall_tp.bpf.c".
/// OVS upcall event
#[event_type]
#[derive(Copy, Default, PartialEq)]
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

impl EventFmt for UpcallEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        write!(
            f,
            "upcall{} port {} cpu {}",
            fmt_upcall_cmd(self.cmd),
            self.port,
            self.cpu
        )
    }
}

// This struct is also used for ebpf decoding.
// Please keep it sync with its ebpf counterpart in
// "bpf/kernel_enqueue.bpf.c".
/// Upcall enqueue event.
#[event_type]
#[derive(Copy, Default, PartialEq)]
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

impl EventFmt for UpcallEnqueueEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        write!(
            f,
            "upcall_enqueue{} ({}/{}) q {} ret {}",
            fmt_upcall_cmd(self.cmd),
            self.upcall_cpu,
            self.upcall_ts,
            self.queue_id,
            self.ret
        )
    }
}

// This struct is also used for ebpf decoding.
// Please keep it sync with its ebpf counterpart in
// "bpf/kernel_upcall_ret.bpf.c".
/// Upcall return event
#[event_type]
#[derive(Copy, Default, PartialEq)]
#[repr(C)]
pub(crate) struct UpcallReturnEvent {
    pub(crate) upcall_ts: u64,
    pub(crate) upcall_cpu: u32,
    pub(crate) ret: i32,
}

impl EventFmt for UpcallReturnEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        write!(
            f,
            "upcall_ret ({}/{}) ret {}",
            self.upcall_cpu, self.upcall_ts, self.ret
        )
    }
}

// This struct is also used for ebpf decoding.
// Please keep it sync with its ebpf counterpart in
// "bpf/include/ovs_operation.h".
/// Operation event.
#[event_type]
#[derive(Copy, Default, PartialEq)]
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

impl EventFmt for OperationEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        write!(
            f,
            "flow_{} q {} ts {} ({})",
            OperationEvent::operation_str(self.op_type).unwrap_or("?"),
            self.queue_id,
            self.batch_ts,
            self.batch_idx
        )
    }
}

// This struct is also used for ebpf decoding.
// Please keep it sync with its ebpf counterpart in
// "bpf/user_recv_upcall.bpf.c".
/// OVS Receive Event
#[event_type]
#[derive(Copy, Default, PartialEq)]
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

impl EventFmt for RecvUpcallEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        // FIXME: there are more fields.
        write!(
            f,
            "upcall_recv q {} pkt_size {}",
            self.queue_id, self.pkt_size
        )
    }
}

/// OVS output action data.
#[event_type]
#[derive(Default, PartialEq)]
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

impl EventFmt for ActionEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        if self.recirc_id != 0 {
            write!(f, "[recirc_id {:#x}] ", self.recirc_id)?;
        }

        write!(f, "exec")?;

        match &self.action {
            OvsAction::Unspecified => write!(f, " (unspecified)")?,
            OvsAction::Output(a) => write!(f, " oport {}", a.port)?,
            OvsAction::Userspace => write!(f, " userspace")?,
            OvsAction::Set => write!(f, " tunnel_set")?,
            OvsAction::PushVlan => write!(f, " push_vlan")?,
            OvsAction::PopVlan => write!(f, " pop_vlan")?,
            OvsAction::Sample => write!(f, " sample")?,
            OvsAction::Recirc(a) => write!(f, " recirc {:#x}", a.id)?,
            OvsAction::Hash => write!(f, " hash")?,
            OvsAction::PushMpls => write!(f, " push_mpls")?,
            OvsAction::PopMpls => write!(f, " pop_mpls")?,
            OvsAction::SetMasked => write!(f, " set_masked")?,
            OvsAction::Ct(ct) => {
                write!(f, " ct zone {}", ct.zone_id)?;

                if let Some(nat) = &ct.nat {
                    write!(f, " nat")?;
                    if let Some(dir) = &nat.dir {
                        match dir {
                            NatDirection::Src => write!(f, "(src")?,
                            NatDirection::Dst => write!(f, "(dst")?,
                        }

                        if ct.flags & R_OVS_CT_NAT_RANGE_MAP_IPS != 0 {
                            if let (Some(min_addr), Some(max_addr)) =
                                (nat.min_addr.as_ref(), nat.max_addr.as_ref())
                            {
                                if min_addr.eq(max_addr) {
                                    write!(f, "={}", min_addr)?;
                                } else {
                                    write!(f, "={}-{}", min_addr, max_addr)?;
                                }
                            }
                        }
                        if ct.flags & R_OVS_CT_NAT_RANGE_PROTO_SPECIFIED != 0 {
                            if let (Some(min_port), Some(max_port)) =
                                (nat.min_port.as_ref(), nat.max_port.as_ref())
                            {
                                if min_port.eq(max_port) {
                                    write!(f, ":{}", min_port)?;
                                } else {
                                    write!(f, ":{}-{}", min_port, max_port)?;
                                }
                            }
                        }
                        write!(f, ")")?;
                    }
                }

                if ct.is_commit()
                    || ct.is_force()
                    || ct.is_persistent()
                    || ct.is_hash()
                    || ct.is_random()
                {
                    let mut flags = Vec::new();
                    if ct.is_commit() {
                        flags.push("commit");
                    }
                    if ct.is_force() {
                        flags.push("force");
                    }
                    if ct.is_persistent() {
                        flags.push("persistent");
                    }
                    if ct.is_hash() {
                        flags.push("hash");
                    }
                    if ct.is_random() {
                        flags.push("random");
                    }
                    write!(f, " {}", flags.join(","))?;
                }
            }
            OvsAction::Trunc => write!(f, " trunc")?,
            OvsAction::PushEth => write!(f, " push_eth")?,
            OvsAction::PopEth => write!(f, " pop_eth")?,
            OvsAction::CtClear => write!(f, " ct_clear")?,
            OvsAction::PushNsh => write!(f, " push_nsh")?,
            OvsAction::PopNsh => write!(f, " pop_nsh")?,
            OvsAction::Meter => write!(f, " meter")?,
            OvsAction::Clone => write!(f, " clone")?,
            OvsAction::CheckPktLen => write!(f, " check_pkt_len")?,
            OvsAction::AddMpls => write!(f, " add_mpls")?,
            OvsAction::DecTtl => write!(f, " dec_ttl")?,
        }

        if let Some(p) = self.queue_id {
            write!(f, " q {}", p)?;
        }

        Ok(())
    }
}

#[event_type_no_py]
#[serde(tag = "action")]
#[derive(Default, PartialEq)]
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
    Recirc(OvsActionRecirc),
    #[serde(rename = "hash")]
    Hash,
    #[serde(rename = "push_mpls")]
    PushMpls,
    #[serde(rename = "pop_mpls")]
    PopMpls,
    #[serde(rename = "set_masked")]
    SetMasked,
    #[serde(rename = "ct")]
    Ct(OvsActionCt),
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

// Please keep it sync with its ebpf counterpart in "bpf/kernel_exec_tp.bpf.c".
/// OVS output action data.
#[event_type]
#[derive(Copy, Default, PartialEq)]
#[repr(C)]
pub(crate) struct OvsActionOutput {
    /// Output port.
    pub(crate) port: u32,
}

// Please keep it sync with its ebpf counterpart in "bpf/kernel_exec_tp.bpf.c".
/// OVS recirc action data.
#[event_type]
#[derive(Copy, Default, PartialEq)]
#[repr(C)]
pub(crate) struct OvsActionRecirc {
    /// Recirculation id.
    pub(crate) id: u32,
}

/// OVS conntrack flags
// Keep in sync with their conterpart in bpf/kernel_exec_tp.bpf.c
pub(super) const R_OVS_CT_COMMIT: u32 = 1 << 0;
pub(super) const R_OVS_CT_FORCE: u32 = 1 << 1;
pub(super) const R_OVS_CT_IP4: u32 = 1 << 2;
pub(super) const R_OVS_CT_IP6: u32 = 1 << 3;
pub(super) const R_OVS_CT_NAT: u32 = 1 << 4;
pub(super) const R_OVS_CT_NAT_SRC: u32 = 1 << 5;
pub(super) const R_OVS_CT_NAT_DST: u32 = 1 << 6;
pub(super) const R_OVS_CT_NAT_RANGE_MAP_IPS: u32 = 1 << 7;
pub(super) const R_OVS_CT_NAT_RANGE_PROTO_SPECIFIED: u32 = 1 << 8;
pub(super) const R_OVS_CT_NAT_RANGE_PROTO_RANDOM: u32 = 1 << 9;
pub(super) const R_OVS_CT_NAT_RANGE_PERSISTENT: u32 = 1 << 10;
pub(super) const R_OVS_CT_NAT_RANGE_PROTO_RANDOM_FULLY: u32 = 1 << 11;

/// OVS conntrack action data.
#[event_type]
#[derive(Default, PartialEq)]
pub(crate) struct OvsActionCt {
    /// Flags
    pub(crate) flags: u32,
    /// Conntrack zone
    pub(crate) zone_id: u16,
    /// NAT
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) nat: Option<OvsActionCtNat>,
}

impl OvsActionCt {
    pub(crate) fn is_commit(&self) -> bool {
        self.flags & R_OVS_CT_COMMIT != 0
    }
    pub(crate) fn is_force(&self) -> bool {
        self.flags & R_OVS_CT_FORCE != 0
    }
    #[allow(dead_code)]
    pub(crate) fn is_ipv4(&self) -> bool {
        self.flags & R_OVS_CT_IP4 != 0
    }
    #[allow(dead_code)]
    pub(crate) fn is_ipv6(&self) -> bool {
        self.flags & R_OVS_CT_IP6 != 0
    }
    pub(crate) fn is_persistent(&self) -> bool {
        self.flags & R_OVS_CT_NAT_RANGE_PERSISTENT != 0
    }
    pub(crate) fn is_hash(&self) -> bool {
        self.flags & R_OVS_CT_NAT_RANGE_PROTO_RANDOM != 0
    }
    pub(crate) fn is_random(&self) -> bool {
        self.flags & R_OVS_CT_NAT_RANGE_PROTO_RANDOM_FULLY != 0
    }
}

#[event_type]
#[derive(Default, PartialEq)]
pub(crate) enum NatDirection {
    #[default]
    #[serde(rename = "src")]
    Src,
    #[serde(rename = "dst")]
    Dst,
}
/// OVS NAT action data.
#[event_type]
#[derive(Default, PartialEq)]
pub(crate) struct OvsActionCtNat {
    /// NAT direction, if any
    pub(crate) dir: Option<NatDirection>,
    /// Minimum address in address range, if any
    pub(crate) min_addr: Option<String>,
    /// Maximum address in address range, if any
    pub(crate) max_addr: Option<String>,
    /// Minimum port in port range, if any
    pub(crate) min_port: Option<u16>,
    /// Maximum port in port range, if any
    pub(crate) max_port: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};
    use serde_json::Value;

    #[test]
    fn test_event_to_from_json() -> Result<()> {
        let events: [(&'static str, OvsEvent); 7] = [
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
            // Conntrack action event
            (
                r#"{"action":"ct","event_type":"action_execute","flags":485,"nat":{"dir":"dst","max_addr":"10.244.1.30","max_port":36900,"min_addr":"10.244.1.3","min_port":36895},"recirc_id":34,"zone_id":20}"#,
                OvsEvent {
                    event: OvsEventType::Action(ActionEvent {
                        action: OvsAction::Ct(OvsActionCt {
                            zone_id: 20,
                            flags: 485,
                            nat: Some(OvsActionCtNat {
                                dir: Some(NatDirection::Dst),
                                min_addr: Some(String::from("10.244.1.3")),
                                max_addr: Some(String::from("10.244.1.30")),
                                min_port: Some(36895),
                                max_port: Some(36900),
                            }),
                        }),
                        recirc_id: 34,
                        queue_id: None,
                    }),
                },
            ),
        ];

        for (event_json, event) in events.iter() {
            let json = serde_json::to_string(event)
                .map_err(|e| anyhow!("Failed to convert event {event:?} to json: {e}"))?;
            // Comparing json strings is error prone. Convert them to Values and compare those.
            assert_eq!(
                serde_json::from_str::<Value>(json.as_str()).unwrap(),
                serde_json::from_str::<Value>(*event_json).unwrap()
            );

            let parsed: OvsEvent = serde_json::from_str(*event_json)
                .map_err(|e| anyhow!("Failed to convert json '{event_json}' to event: {e}"))?;
            assert_eq!(&parsed, event);
        }
        Ok(())
    }
}
