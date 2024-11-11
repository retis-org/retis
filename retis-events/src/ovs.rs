use std::fmt;

use anyhow::{bail, Result};
use serde::{de::Error as Derror, ser::Error as Serror, Deserialize, Deserializer, Serializer};

use super::*;
use crate::{event_section, event_type, Formatter};

///The OVS Event
#[event_section(SectionId::Ovs)]
#[serde(tag = "event_type")]
#[derive(PartialEq)]
pub enum OvsEvent {
    /// Upcall event. It indicates the begining of an upcall. An upcall can have multiple enqueue
    /// events.
    #[serde(rename = "upcall")]
    Upcall {
        #[serde(flatten)]
        upcall: UpcallEvent,
    },

    /// Upcall enqueue event. It indicates a packet (fragment) is enqueued for userspace
    /// processing.
    #[serde(rename = "upcall_enqueue")]
    UpcallEnqueue {
        #[serde(flatten)]
        upcall_enqueue: UpcallEnqueueEvent,
    },

    /// Upcall return event. It indicates an upcall has ended.
    #[serde(rename = "upcall_return")]
    UpcallReturn {
        #[serde(flatten)]
        upcall_return: UpcallReturnEvent,
    },

    /// Receive upcall event. It indicates userspace has received an upcall.
    #[serde(rename = "recv_upcall")]
    RecvUpcall {
        #[serde(flatten)]
        recv_upcall: RecvUpcallEvent,
    },

    /// Operation event. It indicates userspace has executed a flow operation on an upcalled
    /// packet.
    #[serde(rename = "flow_operation")]
    Operation {
        #[serde(flatten)]
        flow_operation: OperationEvent,
    },

    /// Action execution event. It indicates the datapath has executed an action on a packet.
    #[serde(rename = "action_execute")]
    Action {
        #[serde(flatten)]
        action_execute: ActionEvent,
    },

    /// Flow lookup event. It indicates the datapath has successfully perfomed a lookup for a key.
    #[serde(rename = "flow_lookup")]
    DpLookup {
        #[serde(flatten)]
        flow_lookup: LookupEvent,
    },
}

impl EventFmt for OvsEvent {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result {
        use OvsEvent::*;
        let disp: &dyn EventFmt = match self {
            Upcall { upcall } => upcall,
            UpcallEnqueue { upcall_enqueue } => upcall_enqueue,
            UpcallReturn { upcall_return } => upcall_return,
            RecvUpcall { recv_upcall } => recv_upcall,
            Operation { flow_operation } => flow_operation,
            Action { action_execute } => action_execute,
            DpLookup { flow_lookup } => flow_lookup,
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

/// OVS upcall event
#[event_type]
#[derive(Copy, Default, PartialEq)]
pub struct UpcallEvent {
    /// Upcall command. Holds OVS_PACKET_CMD:
    ///   OVS_PACKET_CMD_UNSPEC   = 0
    ///   OVS_PACKET_CMD_MISS     = 1
    ///   OVS_PACKET_CMD_ACTION   = 2
    ///   OVS_PACKET_CMD_EXECUTE  = 3
    pub cmd: u8,
    /// Upcall port.
    pub port: u32,
    /// Cpu ID
    pub cpu: u32,
}

impl EventFmt for UpcallEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(
            f,
            "upcall{} port {} cpu {}",
            fmt_upcall_cmd(self.cmd),
            self.port,
            self.cpu
        )
    }
}

fn fmt_ufid(ufid: &[u32]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:04x}{:08x}",
        ufid[0],
        ufid[1] >> 16,
        ufid[1] & 0xffff,
        ufid[2] >> 16,
        ufid[2] & 0xffff,
        ufid[3]
    )
}

#[event_type]
#[derive(Copy, Default, PartialEq)]
pub struct Ufid(pub [u32; 4]);

impl fmt::Display for Ufid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:04x}-{:04x}{:08x}",
            self.0[0],
            self.0[1] >> 16,
            self.0[1] & 0xffff,
            self.0[2] >> 16,
            self.0[2] & 0xffff,
            self.0[3]
        )
    }
}

/// OVS lookup event
#[event_type]
#[derive(Copy, Default, PartialEq)]
pub struct LookupEvent {
    /// flow pointer
    pub flow: u64,
    /// actions pointer
    pub sf_acts: u64,
    /// Flow UFID.
    pub ufid: Ufid,
    /// n_mask_hit.
    pub n_mask_hit: u32,
    /// n_cache_hit.
    pub n_cache_hit: u32,
}

impl EventFmt for LookupEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(
            f,
            "ufid {} hit (mask/cache) {}/{} flow {:x} sf_acts {:x}",
            self.ufid, self.n_mask_hit, self.n_cache_hit, self.flow, self.sf_acts,
        )
    }
}

/// Upcall enqueue event.
#[event_type]
#[derive(Copy, Default, PartialEq)]
pub struct UpcallEnqueueEvent {
    /// Return code. Any value different from zero indicates the upcall enqueue
    /// failed probably indicating a packet drop.
    pub ret: i32,
    /// Upcall command executed.
    pub cmd: u8,
    /// Upcall port id.
    pub port: u32,
    /// Timestamp of the associated UpcallEvent.
    pub upcall_ts: u64,
    /// CPU id of the associated UpcallEvent.
    pub upcall_cpu: u32,
    /// Enqueue id used for tracking.
    pub queue_id: u32,
}

impl EventFmt for UpcallEnqueueEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
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

/// Upcall return event
#[event_type]
#[derive(Copy, Default, PartialEq)]
pub struct UpcallReturnEvent {
    pub upcall_ts: u64,
    pub upcall_cpu: u32,
    pub ret: i32,
}

impl EventFmt for UpcallReturnEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(
            f,
            "upcall_ret ({}/{}) ret {}",
            self.upcall_cpu, self.upcall_ts, self.ret
        )
    }
}

/// Operation event.
#[event_type]
#[derive(Copy, Default, PartialEq)]
#[repr(C)]
pub struct OperationEvent {
    /// Operation type ("put" or "exec")
    #[serde(
        deserialize_with = "OperationEvent::deserialize_op",
        serialize_with = "OperationEvent::serialize_op"
    )]
    pub op_type: u8,
    /// Queue id used for tracking
    pub queue_id: u32,
    /// Timestamp of the begining of batch
    pub batch_ts: u64,
    /// Index within the batch
    pub batch_idx: u8,
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
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
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

/// OVS Receive Event
#[event_type]
#[derive(Copy, Default, PartialEq)]
pub struct RecvUpcallEvent {
    /// Type of upcall
    pub r#type: u32,
    /// Packet size
    pub pkt_size: u32,
    /// Key size
    pub key_size: u64,
    /// Queue id used for tracking
    pub queue_id: u32,
    /// Timestamp of the begining of batch
    pub batch_ts: u64,
    /// Index within the batch
    pub batch_idx: u8,
}

impl EventFmt for RecvUpcallEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
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
pub struct ActionEvent {
    /// Action to be executed.
    #[serde(flatten)]
    pub action: Option<OvsAction>,
    /// Recirculation id.
    pub recirc_id: u32,
    /// Queue id used for tracking. None if not tracking or if the output event did not come from
    /// an upcall.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_id: Option<u32>,
}

impl EventFmt for ActionEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        if self.recirc_id != 0 {
            write!(f, "[recirc_id {:#x}] ", self.recirc_id)?;
        }

        write!(f, "exec")?;

        match &self.action {
            Some(OvsAction::Output { output }) => write!(f, " oport {}", output.port)?,
            Some(OvsAction::Userspace(_)) => write!(f, " userspace")?,
            Some(OvsAction::Set(_)) => write!(f, " tunnel_set")?,
            Some(OvsAction::PushVlan(_)) => write!(f, " push_vlan")?,
            Some(OvsAction::PopVlan(_)) => write!(f, " pop_vlan")?,
            Some(OvsAction::Sample(_)) => write!(f, " sample")?,
            Some(OvsAction::Recirc { recirc }) => write!(f, " recirc {:#x}", recirc.id)?,
            Some(OvsAction::Hash(_)) => write!(f, " hash")?,
            Some(OvsAction::PushMpls(_)) => write!(f, " push_mpls")?,
            Some(OvsAction::PopMpls(_)) => write!(f, " pop_mpls")?,
            Some(OvsAction::SetMasked(_)) => write!(f, " set_masked")?,
            Some(OvsAction::Ct { ct }) => {
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
            Some(OvsAction::Trunc(_)) => write!(f, " trunc")?,
            Some(OvsAction::PushEth(_)) => write!(f, " push_eth")?,
            Some(OvsAction::PopEth(_)) => write!(f, " pop_eth")?,
            Some(OvsAction::CtClear(_)) => write!(f, " ct_clear")?,
            Some(OvsAction::PushNsh(_)) => write!(f, " push_nsh")?,
            Some(OvsAction::PopNsh(_)) => write!(f, " pop_nsh")?,
            Some(OvsAction::Meter(_)) => write!(f, " meter")?,
            Some(OvsAction::Clone(_)) => write!(f, " clone")?,
            Some(OvsAction::CheckPktLen(_)) => write!(f, " check_pkt_len")?,
            Some(OvsAction::AddMpls(_)) => write!(f, " add_mpls")?,
            Some(OvsAction::DecTtl(_)) => write!(f, " dec_ttl")?,
            Some(OvsAction::Drop { reason }) => write!(f, " drop {}", reason)?,
            None => write!(f, " unspec")?,
        }

        if let Some(p) = self.queue_id {
            write!(f, " q {}", p)?;
        }

        Ok(())
    }
}

// Adding unit values in an otherwise complex is not supported by pyo3.
// FIXME: Remove when arguments from all actions are implemented.
#[event_type]
#[derive(PartialEq)]
pub struct OvsDummyAction;

#[event_type]
#[serde(tag = "action")]
#[derive(PartialEq)]
pub enum OvsAction {
    #[serde(rename = "output")]
    Output {
        #[serde(flatten)]
        output: OvsActionOutput,
    },
    #[serde(rename = "userspace")]
    Userspace(OvsDummyAction),
    #[serde(rename = "set")]
    Set(OvsDummyAction),
    #[serde(rename = "push_vlan")]
    PushVlan(OvsDummyAction),
    #[serde(rename = "pop_vlan")]
    PopVlan(OvsDummyAction),
    #[serde(rename = "sample")]
    Sample(OvsDummyAction),
    #[serde(rename = "recirc")]
    Recirc {
        #[serde(flatten)]
        recirc: OvsActionRecirc,
    },
    #[serde(rename = "hash")]
    Hash(OvsDummyAction),
    #[serde(rename = "push_mpls")]
    PushMpls(OvsDummyAction),
    #[serde(rename = "pop_mpls")]
    PopMpls(OvsDummyAction),
    #[serde(rename = "set_masked")]
    SetMasked(OvsDummyAction),
    #[serde(rename = "ct")]
    Ct {
        #[serde(flatten)]
        ct: OvsActionCt,
    },
    #[serde(rename = "trunc")]
    Trunc(OvsDummyAction),
    #[serde(rename = "push_eth")]
    PushEth(OvsDummyAction),
    #[serde(rename = "pop_eth")]
    PopEth(OvsDummyAction),
    #[serde(rename = "ct_clear")]
    CtClear(OvsDummyAction),
    #[serde(rename = "push_nsh")]
    PushNsh(OvsDummyAction),
    #[serde(rename = "pop_nsh")]
    PopNsh(OvsDummyAction),
    #[serde(rename = "meter")]
    Meter(OvsDummyAction),
    #[serde(rename = "clone")]
    Clone(OvsDummyAction),
    #[serde(rename = "check_pkt_len")]
    CheckPktLen(OvsDummyAction),
    #[serde(rename = "add_mpls")]
    AddMpls(OvsDummyAction),
    #[serde(rename = "dec_ttl")]
    DecTtl(OvsDummyAction),
    #[serde(rename = "drop")]
    Drop { reason: u32 },
}

/// OVS output action data.
#[event_type]
#[derive(Copy, Default, PartialEq)]
pub struct OvsActionOutput {
    /// Output port.
    pub port: u32,
}

/// OVS recirc action data.
#[event_type]
#[derive(Copy, Default, PartialEq)]
pub struct OvsActionRecirc {
    /// Recirculation id.
    pub id: u32,
}

/// OVS conntrack flags
pub const R_OVS_CT_COMMIT: u32 = 1 << 0;
pub const R_OVS_CT_FORCE: u32 = 1 << 1;
pub const R_OVS_CT_IP4: u32 = 1 << 2;
pub const R_OVS_CT_IP6: u32 = 1 << 3;
pub const R_OVS_CT_NAT: u32 = 1 << 4;
pub const R_OVS_CT_NAT_SRC: u32 = 1 << 5;
pub const R_OVS_CT_NAT_DST: u32 = 1 << 6;
pub const R_OVS_CT_NAT_RANGE_MAP_IPS: u32 = 1 << 7;
pub const R_OVS_CT_NAT_RANGE_PROTO_SPECIFIED: u32 = 1 << 8;
pub const R_OVS_CT_NAT_RANGE_PROTO_RANDOM: u32 = 1 << 9;
pub const R_OVS_CT_NAT_RANGE_PERSISTENT: u32 = 1 << 10;
pub const R_OVS_CT_NAT_RANGE_PROTO_RANDOM_FULLY: u32 = 1 << 11;

/// OVS conntrack action data.
#[event_type]
#[derive(Default, PartialEq)]
pub struct OvsActionCt {
    /// Flags
    pub flags: u32,
    /// Conntrack zone
    pub zone_id: u16,
    /// NAT
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nat: Option<OvsActionCtNat>,
}

impl OvsActionCt {
    pub fn is_commit(&self) -> bool {
        self.flags & R_OVS_CT_COMMIT != 0
    }
    pub fn is_force(&self) -> bool {
        self.flags & R_OVS_CT_FORCE != 0
    }
    #[allow(dead_code)]
    pub fn is_ipv4(&self) -> bool {
        self.flags & R_OVS_CT_IP4 != 0
    }
    #[allow(dead_code)]
    pub fn is_ipv6(&self) -> bool {
        self.flags & R_OVS_CT_IP6 != 0
    }
    pub fn is_persistent(&self) -> bool {
        self.flags & R_OVS_CT_NAT_RANGE_PERSISTENT != 0
    }
    pub fn is_hash(&self) -> bool {
        self.flags & R_OVS_CT_NAT_RANGE_PROTO_RANDOM != 0
    }
    pub fn is_random(&self) -> bool {
        self.flags & R_OVS_CT_NAT_RANGE_PROTO_RANDOM_FULLY != 0
    }
}

#[event_type]
#[derive(Default)]
pub enum NatDirection {
    #[default]
    #[serde(rename = "src")]
    Src,
    #[serde(rename = "dst")]
    Dst,
}
/// OVS NAT action data.
#[event_type]
#[derive(Default, PartialEq)]
pub struct OvsActionCtNat {
    /// NAT direction, if any
    pub dir: Option<NatDirection>,
    /// Minimum address in address range, if any
    pub min_addr: Option<String>,
    /// Maximum address in address range, if any
    pub max_addr: Option<String>,
    /// Minimum port in port range, if any
    pub min_port: Option<u16>,
    /// Maximum port in port range, if any
    pub max_port: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};
    use serde_json::Value;

    #[test]
    fn test_event_to_from_json() -> Result<()> {
        let events: [(&'static str, OvsEvent); 8] = [
            // Upcall event
            (
                r#"{"cmd":1,"cpu":0,"event_type":"upcall","port":4195744766}"#,
                OvsEvent::Upcall {
                    upcall: UpcallEvent {
                        cmd: 1,
                        cpu: 0,
                        port: 4195744766,
                    },
                },
            ),
            // Action event
            (
                r#"{"action":"output","event_type":"action_execute","port":2,"queue_id":1361394472,"recirc_id":0}"#,
                OvsEvent::Action {
                    action_execute: ActionEvent {
                        action: Some(OvsAction::Output {
                            output: OvsActionOutput { port: 2 },
                        }),
                        recirc_id: 0,
                        queue_id: Some(1361394472),
                    },
                },
            ),
            // Upcall enqueue event
            (
                r#"{"cmd":1,"event_type":"upcall_enqueue","queue_id":3316322986,"ret":0,"upcall_cpu":0,"port":4195744766,"upcall_ts":61096236973661}"#,
                OvsEvent::UpcallEnqueue {
                    upcall_enqueue: UpcallEnqueueEvent {
                        ret: 0,
                        cmd: 1,
                        port: 4195744766,
                        upcall_ts: 61096236973661,
                        upcall_cpu: 0,
                        queue_id: 3316322986,
                    },
                },
            ),
            // Upcall return event
            (
                r#"{"event_type":"upcall_return","ret":0,"upcall_cpu":0,"upcall_ts":61096236973661}"#,
                OvsEvent::UpcallReturn {
                    upcall_return: UpcallReturnEvent {
                        ret: 0,
                        upcall_ts: 61096236973661,
                        upcall_cpu: 0,
                    },
                },
            ),
            // Operation event exec
            (
                r#"{"batch_idx":0,"batch_ts":61096237019698,"event_type":"flow_operation","op_type":"exec","queue_id":3316322986}"#,
                OvsEvent::Operation {
                    flow_operation: OperationEvent {
                        op_type: 0,
                        queue_id: 3316322986,
                        batch_ts: 61096237019698,
                        batch_idx: 0,
                    },
                },
            ),
            // Operation event put
            (
                r#"{"batch_idx":0,"batch_ts":61096237019698,"event_type":"flow_operation","op_type":"put","queue_id":3316322986}"#,
                OvsEvent::Operation {
                    flow_operation: OperationEvent {
                        op_type: 1,
                        queue_id: 3316322986,
                        batch_ts: 61096237019698,
                        batch_idx: 0,
                    },
                },
            ),
            // Conntrack action event
            (
                r#"{"action":"ct","event_type":"action_execute","flags":485,"nat":{"dir":"dst","max_addr":"10.244.1.30","max_port":36900,"min_addr":"10.244.1.3","min_port":36895},"recirc_id":34,"zone_id":20}"#,
                OvsEvent::Action {
                    action_execute: ActionEvent {
                        action: Some(OvsAction::Ct {
                            ct: OvsActionCt {
                                zone_id: 20,
                                flags: 485,
                                nat: Some(OvsActionCtNat {
                                    dir: Some(NatDirection::Dst),
                                    min_addr: Some(String::from("10.244.1.3")),
                                    max_addr: Some(String::from("10.244.1.30")),
                                    min_port: Some(36895),
                                    max_port: Some(36900),
                                }),
                            },
                        }),
                        recirc_id: 34,
                        queue_id: None,
                    },
                },
            ),
            // Drop action event
            (
                r#"{"action":"drop","event_type":"action_execute","reason":0,"recirc_id":32}"#,
                OvsEvent::Action {
                    action_execute: ActionEvent {
                        action: Some(OvsAction::Drop { reason: 0 }),
                        recirc_id: 32,
                        queue_id: None,
                    },
                },
            ),
        ];

        for (event_json, event) in events.iter() {
            let json = serde_json::to_string(event)
                .map_err(|e| anyhow!("Failed to convert event {event:?} to json: {e}"))?;
            // Comparing json strings is error prone. Convert them to Values and compare those.
            assert_eq!(
                serde_json::from_str::<Value>(json.as_str()).unwrap(),
                serde_json::from_str::<Value>(event_json).unwrap()
            );

            let parsed: OvsEvent = serde_json::from_str(event_json)
                .map_err(|e| anyhow!("Failed to convert json '{event_json}' to event: {e}"))?;
            assert_eq!(&parsed, event);
        }
        Ok(())
    }
}
