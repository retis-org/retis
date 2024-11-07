//! Rust<>BPF types definitions for the ovs module.
//! Many parts of the OvsEvent (defined in retis-events) are used directly to parse
//! the bpf raw event. Please keep them in sync.

use std::collections::HashMap;
use std::net::Ipv6Addr;

use anyhow::{anyhow, bail, Result};

use crate::{
    bindings::{
        kernel_enqueue_uapi::upcall_enqueue_event,
        kernel_exec_tp_uapi::{
            exec_ct, exec_drop, exec_event, exec_output, exec_recirc, exec_track_event,
        },
        kernel_flow_tbl_lookup_ret_uapi::flow_lookup_ret_event,
        kernel_upcall_ret_uapi::upcall_ret_event,
        kernel_upcall_tp_uapi::upcall_event,
        ovs_operation_uapi::ovs_operation_event,
        user_recv_upcall_uapi::recv_upcall_event,
    },
    core::events::{
        parse_enum, parse_raw_section, BpfRawSection, EventSectionFactory, FactoryId,
        RawEventSectionFactory,
    },
    event_section_factory,
    events::*,
    helpers,
};

/// Event data types supported by the ovs module.
#[derive(Debug, Eq, Hash, PartialEq)]
pub(crate) enum OvsDataType {
    /// Upcall tracepoint.
    Upcall = 0,
    /// Upcall enqueue kretprobe.
    UpcallEnqueue = 1,
    /// Upcall return.
    UpcallReturn = 2,
    /// Upcall received in userspace.
    RecvUpcall = 3,
    /// Flow operation
    Operation = 4,
    /// Execute action tracepoint.
    ActionExec = 5,
    /// Execute action tracking.
    ActionExecTrack = 6,
    // OUTPUT action specific data.
    OutputAction = 7,
    /// Recirculate action.
    RecircAction = 8,
    /// Conntrack action.
    ConntrackAction = 9,
    /// Explicit drop action.
    DropAction = 10,
    /// Flow lookup
    FlowLookup = 11,
}

impl OvsDataType {
    pub(super) fn from_u8(val: u8) -> Result<OvsDataType> {
        use OvsDataType::*;
        Ok(match val {
            0 => Upcall,
            1 => UpcallEnqueue,
            2 => UpcallReturn,
            3 => RecvUpcall,
            4 => Operation,
            5 => ActionExec,
            6 => ActionExecTrack,
            7 => OutputAction,
            8 => RecircAction,
            9 => ConntrackAction,
            10 => DropAction,
            11 => FlowLookup,
            x => bail!("Can't construct a OvsDataType from {}", x),
        })
    }
}

pub(super) fn unmarshall_flow_lookup(raw_section: &BpfRawSection) -> Result<OvsEvent> {
    let raw = parse_raw_section::<flow_lookup_ret_event>(raw_section)?;
    Ok(OvsEvent::DpLookup {
        flow_lookup: LookupEvent {
            flow: raw.flow as usize as u64,
            sf_acts: raw.sf_acts as usize as u64,
            ufid: Ufid::from(raw.ufid),
            n_mask_hit: raw.n_mask_hit,
            n_cache_hit: raw.n_cache_hit,
        },
    })
}

pub(super) fn unmarshall_upcall(raw_section: &BpfRawSection) -> Result<OvsEvent> {
    let raw = parse_raw_section::<upcall_event>(raw_section)?;
    Ok(OvsEvent::Upcall {
        upcall: UpcallEvent {
            cmd: raw.cmd,
            port: raw.port,
            cpu: raw.cpu,
        },
    })
}

pub(super) fn unmarshall_exec_track(
    raw_section: &BpfRawSection,
    event: &mut OvsEvent,
) -> Result<()> {
    let raw = parse_raw_section::<exec_track_event>(raw_section)?;

    match event {
        OvsEvent::Action {
            ref mut action_execute,
        } => action_execute.queue_id = Some(raw.queue_id),
        other => {
            bail!(
                "Conflicting OVS event types. Received {:?} data type but event is already {:#?}",
                OvsDataType::ActionExecTrack,
                other
            );
        }
    }
    Ok(())
}

fn update_action_event(event: &mut OvsEvent, action: OvsAction) -> Result<()> {
    match event {
        OvsEvent::Action {
            ref mut action_execute,
        } => action_execute.action = Some(action),
        other => {
            bail!(
                "Conflicting OVS event types. Received {:?} data type but event is already {:#?}",
                action,
                other
            );
        }
    }
    Ok(())
}

pub(super) fn unmarshall_output(raw_section: &BpfRawSection, event: &mut OvsEvent) -> Result<()> {
    let raw = parse_raw_section::<exec_output>(raw_section)?;

    update_action_event(
        event,
        OvsAction::Output {
            output: OvsActionOutput { port: raw.port },
        },
    )
}

pub(super) fn unmarshall_recirc(raw_section: &BpfRawSection, event: &mut OvsEvent) -> Result<()> {
    let raw = parse_raw_section::<exec_recirc>(raw_section)?;
    update_action_event(
        event,
        OvsAction::Recirc {
            recirc: OvsActionRecirc { id: raw.id },
        },
    )
}

pub(super) fn unmarshall_drop(raw_section: &BpfRawSection, event: &mut OvsEvent) -> Result<()> {
    let raw = parse_raw_section::<exec_drop>(raw_section)?;

    update_action_event(event, OvsAction::Drop { reason: raw.reason })
}

pub(super) fn unmarshall_ct(raw_section: &BpfRawSection, event: &mut OvsEvent) -> Result<()> {
    let raw = parse_raw_section::<exec_ct>(raw_section)?;
    let nat = if raw.flags & R_OVS_CT_NAT != 0 {
        let flags = raw.flags;
        let dir = match flags {
            f if f & R_OVS_CT_NAT_SRC != 0 => Some(NatDirection::Src),
            f if f & R_OVS_CT_NAT_DST != 0 => Some(NatDirection::Dst),
            _ => None,
        };

        let (min_addr, max_addr) = if raw.flags & R_OVS_CT_NAT_RANGE_MAP_IPS != 0 {
            if raw.flags & R_OVS_CT_IP4 != 0 {
                let min_addr = unsafe { raw.min.addr4 };
                let max_addr = unsafe { raw.max.addr4 };
                (
                    Some(helpers::net::parse_ipv4_addr(u32::from_be(min_addr))?),
                    Some(helpers::net::parse_ipv4_addr(u32::from_be(max_addr))?),
                )
            } else if raw.flags & R_OVS_CT_IP6 != 0 {
                let min_addr = unsafe { raw.min.addr6 };
                let max_addr = unsafe { raw.max.addr6 };
                (
                    Some(Ipv6Addr::from(u128::from_be_bytes(min_addr)).to_string()),
                    Some(Ipv6Addr::from(u128::from_be_bytes(max_addr)).to_string()),
                )
            } else {
                bail!("Unknown ct address family");
            }
        } else {
            (None, None)
        };

        let (min_port, max_port) = if raw.flags & R_OVS_CT_NAT_RANGE_PROTO_SPECIFIED != 0 {
            (
                Some(u16::from_be(raw.min_port)),
                Some(u16::from_be(raw.max_port)),
            )
        } else {
            (None, None)
        };
        Some(OvsActionCtNat {
            dir,
            min_addr,
            max_addr,
            min_port,
            max_port,
        })
    } else {
        None
    };

    let ct = OvsActionCt {
        flags: raw.flags,
        zone_id: raw.zone_id,
        nat,
    };
    update_action_event(event, OvsAction::Ct { ct })
}

pub(super) fn unmarshall_recv(raw_section: &BpfRawSection) -> Result<OvsEvent> {
    let raw = parse_raw_section::<recv_upcall_event>(raw_section)?;

    Ok(OvsEvent::RecvUpcall {
        recv_upcall: RecvUpcallEvent {
            key_size: raw.key_size,
            batch_ts: raw.batch_ts,
            pkt_size: raw.pkt_size,
            queue_id: raw.queue_id,
            r#type: raw.type_,
            batch_idx: raw.batch_idx,
        },
    })
}

pub(super) fn unmarshall_operation(raw_section: &BpfRawSection) -> Result<OvsEvent> {
    let raw = parse_raw_section::<ovs_operation_event>(raw_section)?;

    Ok(OvsEvent::Operation {
        flow_operation: OperationEvent {
            batch_ts: raw.batch_ts,
            queue_id: raw.queue_id,
            batch_idx: raw.batch_idx,
            op_type: raw.type_,
        },
    })
}

pub(super) fn unmarshall_upcall_enqueue(raw_section: &BpfRawSection) -> Result<OvsEvent> {
    let raw = parse_raw_section::<upcall_enqueue_event>(raw_section)?;

    Ok(OvsEvent::UpcallEnqueue {
        upcall_enqueue: UpcallEnqueueEvent {
            ret: raw.ret,
            cmd: raw.cmd,
            port: raw.port,
            upcall_ts: raw.upcall_ts,
            upcall_cpu: raw.upcall_cpu,
            queue_id: raw.queue_id,
        },
    })
}

pub(super) fn unmarshall_upcall_return(raw_section: &BpfRawSection) -> Result<OvsEvent> {
    let raw = parse_raw_section::<upcall_ret_event>(raw_section)?;

    Ok(OvsEvent::UpcallReturn {
        upcall_return: UpcallReturnEvent {
            upcall_ts: raw.upcall_ts,
            upcall_cpu: raw.upcall_cpu,
            ret: raw.ret,
        },
    })
}

#[event_section_factory(FactoryId::Ovs)]
#[derive(Default)]
pub(crate) struct OvsEventFactory {
    ovs_actions: HashMap<u32, String>,
}

impl OvsEventFactory {
    pub fn new() -> Result<Self> {
        let ovs_actions = if cfg!(feature = "benchmark") {
            // Add a few dummy actions for benchmarking
            HashMap::from([(1, "OUTPUT".to_string()), (2, "USERSPACE".to_string())])
        } else {
            parse_enum("ovs_action_attr", &["OVS_ACTION_ATTR_"])?
        };
        Ok(OvsEventFactory { ovs_actions })
    }

    fn unmarshall_exec(&self, raw_section: &BpfRawSection) -> Result<OvsEvent> {
        let raw = parse_raw_section::<exec_event>(raw_section)?;

        // When we implement event data types for every action we will be able to create the
        // specific action variant when unmarshaling its event data type. Until then, we need to
        // initialize the Action here based on the action_id (which corresponds to ovs_action_attr
        // defined in uapi/linux/openvswitch.h).
        Ok(OvsEvent::Action {
            action_execute: ActionEvent {
                action: match self
                    .ovs_actions
                    .get(&(raw.action as u32))
                    .map(|s| s.as_str())
                {
                    Some("NONE") => None,
                    Some("OUTPUT") => Some(OvsAction::Output {
                        output: OvsActionOutput::default(),
                    }),
                    Some("USERSPACE") => Some(OvsAction::Userspace(OvsDummyAction)),
                    Some("SET") => Some(OvsAction::Set(OvsDummyAction)),
                    Some("PUSH_VLAN") => Some(OvsAction::PushVlan(OvsDummyAction)),
                    Some("POP_VLAN") => Some(OvsAction::PopVlan(OvsDummyAction)),
                    Some("SAMPLE") => Some(OvsAction::Sample(OvsDummyAction)),
                    Some("RECIRC") => Some(OvsAction::Recirc {
                        recirc: OvsActionRecirc::default(),
                    }),
                    Some("HASH") => Some(OvsAction::Hash(OvsDummyAction)),
                    Some("PUSH_MPLS") => Some(OvsAction::PushMpls(OvsDummyAction)),
                    Some("POP_MPLS") => Some(OvsAction::PopMpls(OvsDummyAction)),
                    Some("SET_MASKED") => Some(OvsAction::SetMasked(OvsDummyAction)),
                    Some("CT") => Some(OvsAction::Ct {
                        ct: OvsActionCt::default(),
                    }),
                    Some("TRUNC") => Some(OvsAction::Trunc(OvsDummyAction)),
                    Some("PUSH_ETH") => Some(OvsAction::PushEth(OvsDummyAction)),
                    Some("POP_ETH") => Some(OvsAction::PopEth(OvsDummyAction)),
                    Some("CT_CLEAR") => Some(OvsAction::CtClear(OvsDummyAction)),
                    Some("PUSH_NSH") => Some(OvsAction::PushNsh(OvsDummyAction)),
                    Some("POP_NSH") => Some(OvsAction::PopNsh(OvsDummyAction)),
                    Some("METER") => Some(OvsAction::Meter(OvsDummyAction)),
                    Some("CLONE") => Some(OvsAction::Clone(OvsDummyAction)),
                    Some("CHECK_PKT_LEN") => Some(OvsAction::CheckPktLen(OvsDummyAction)),
                    Some("ADD_MPLS") => Some(OvsAction::AddMpls(OvsDummyAction)),
                    Some("DEC_TTL") => Some(OvsAction::DecTtl(OvsDummyAction)),
                    Some("DROP") => Some(OvsAction::Drop { reason: 0 }),
                    // The private OVS_ACTION_ATTR_SET_TO_MASKED action is used
                    // in the same way as OVS_ACTION_ATTR_SET_MASKED. Use only
                    // one action to avoid confusion
                    Some("SET_TO_MASKED") => Some(OvsAction::SetMasked(OvsDummyAction)),
                    _ => bail!("Unsupported action id {}", raw.action),
                },
                recirc_id: raw.recirc_id,
                ..ActionEvent::default()
            },
        })
    }
}

impl RawEventSectionFactory for OvsEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut event = None; // = OvsEvent::default();

        for section in raw_sections.iter() {
            match OvsDataType::from_u8(section.header.data_type)? {
                OvsDataType::Upcall => {
                    event = Some(unmarshall_upcall(section)?);
                }
                OvsDataType::UpcallEnqueue => {
                    event = Some(unmarshall_upcall_enqueue(section)?);
                }
                OvsDataType::UpcallReturn => {
                    event = Some(unmarshall_upcall_return(section)?);
                }
                OvsDataType::RecvUpcall => {
                    event = Some(unmarshall_recv(section)?);
                }
                OvsDataType::Operation => {
                    event = Some(unmarshall_operation(section)?);
                }
                OvsDataType::ActionExec => {
                    event = Some(self.unmarshall_exec(section)?);
                }
                OvsDataType::FlowLookup => {
                    event = Some(unmarshall_flow_lookup(section)?);
                }
                OvsDataType::ActionExecTrack => unmarshall_exec_track(
                    section,
                    event
                        .as_mut()
                        .ok_or_else(|| anyhow!("received action track without action"))?,
                )?,
                OvsDataType::OutputAction => unmarshall_output(
                    section,
                    event
                        .as_mut()
                        .ok_or_else(|| anyhow!("received action data without action"))?,
                )?,
                OvsDataType::RecircAction => unmarshall_recirc(
                    section,
                    event
                        .as_mut()
                        .ok_or_else(|| anyhow!("received action data without action"))?,
                )?,
                OvsDataType::ConntrackAction => unmarshall_ct(
                    section,
                    event
                        .as_mut()
                        .ok_or_else(|| anyhow!("received action data without action"))?,
                )?,
                OvsDataType::DropAction => unmarshall_drop(
                    section,
                    event
                        .as_mut()
                        .ok_or_else(|| anyhow!("received action data without action"))?,
                )?,
            };
        }

        Ok(Box::new(
            event.ok_or_else(|| anyhow!("Incomplete OVS event"))?,
        ))
    }
}

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use super::*;
    use crate::{benchmark::helpers::*, core::events::FactoryId};

    impl RawSectionBuilder for exec_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self {
                action: 1,
                recirc_id: 3,
            };
            build_raw_section(
                out,
                FactoryId::Ovs as u8,
                OvsDataType::ActionExec as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }
}
