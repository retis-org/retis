//! Rust<>BPF types definitions for the ovs module.
//! Many parts of the OvsEvent (defined in retis-events) are used directly to parse
//! the bpf raw event. Please keep them in sync.

use std::net::Ipv6Addr;

use anyhow::{anyhow, bail, Result};

use crate::{
    core::events::{
        parse_raw_section, BpfRawSection, EventSectionFactory, FactoryId, RawEventSectionFactory,
    },
    event_section_factory,
    events::*,
    helpers, raw_event_section,
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
            x => bail!("Can't construct a OvsDataType from {}", x),
        })
    }
}

pub(super) fn unmarshall_upcall(raw_section: &BpfRawSection) -> Result<OvsEvent> {
    let upcall = parse_raw_section::<UpcallEvent>(raw_section)?;
    Ok(OvsEvent {
        event: OvsEventType::Upcall(*upcall),
    })
}

/// OVS action event data.
#[raw_event_section]
pub(crate) struct BpfActionEvent {
    /// Action to be executed.
    action: u8,
    /// Recirculation id.
    recirc_id: u32,
}

pub(super) fn unmarshall_exec(raw_section: &BpfRawSection) -> Result<OvsEvent> {
    let raw = parse_raw_section::<BpfActionEvent>(raw_section)?;

    // When we implement event data types for every action we will be able to create the
    // specific action variant when unmarshaling its event data type. Until then, we need to
    // initialize the Action here based on the action_id (which corresponds to ovs_action_attr
    // defined in uapi/linux/openvswitch.h).
    Ok(OvsEvent {
        event: OvsEventType::Action(ActionEvent {
            action: match raw.action {
                0 => None,
                1 => Some(OvsAction::Output(OvsActionOutput::default())),
                2 => Some(OvsAction::Userspace(OvsDummyAction)),
                3 => Some(OvsAction::Set(OvsDummyAction)),
                4 => Some(OvsAction::PushVlan(OvsDummyAction)),
                5 => Some(OvsAction::PopVlan(OvsDummyAction)),
                6 => Some(OvsAction::Sample(OvsDummyAction)),
                7 => Some(OvsAction::Recirc(OvsActionRecirc::default())),
                8 => Some(OvsAction::Hash(OvsDummyAction)),
                9 => Some(OvsAction::PushMpls(OvsDummyAction)),
                10 => Some(OvsAction::PopMpls(OvsDummyAction)),
                11 => Some(OvsAction::SetMasked(OvsDummyAction)),
                12 => Some(OvsAction::Ct(OvsActionCt::default())),
                13 => Some(OvsAction::Trunc(OvsDummyAction)),
                14 => Some(OvsAction::PushEth(OvsDummyAction)),
                15 => Some(OvsAction::PopEth(OvsDummyAction)),
                16 => Some(OvsAction::CtClear(OvsDummyAction)),
                17 => Some(OvsAction::PushNsh(OvsDummyAction)),
                18 => Some(OvsAction::PopNsh(OvsDummyAction)),
                19 => Some(OvsAction::Meter(OvsDummyAction)),
                20 => Some(OvsAction::Clone(OvsDummyAction)),
                21 => Some(OvsAction::CheckPktLen(OvsDummyAction)),
                22 => Some(OvsAction::AddMpls(OvsDummyAction)),
                23 => Some(OvsAction::DecTtl(OvsDummyAction)),
                // The private OVS_ACTION_ATTR_SET_TO_MASKED action is used
                // in the same way as OVS_ACTION_ATTR_SET_MASKED. Use only
                // one action to avoid confusion
                25 => Some(OvsAction::SetMasked(OvsDummyAction)),
                val => bail!("Unsupported action id {val}"),
            },
            recirc_id: raw.recirc_id,
            ..ActionEvent::default()
        }),
    })
}

/// OVS action tracking event data.
#[raw_event_section]
struct BpfActionTrackEvent {
    /// Queue id.
    queue_id: u32,
}

pub(super) fn unmarshall_exec_track(
    raw_section: &BpfRawSection,
    event: &mut OvsEvent,
) -> Result<()> {
    let raw = parse_raw_section::<BpfActionTrackEvent>(raw_section)?;

    match &mut event.event {
        OvsEventType::Action(ref mut action) => action.queue_id = Some(raw.queue_id),
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
    match &mut event.event {
        OvsEventType::Action(ref mut event) => event.action = Some(action),
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
    let output = parse_raw_section::<OvsActionOutput>(raw_section)?;

    update_action_event(event, OvsAction::Output(*output))
}

pub(super) fn unmarshall_recirc(raw_section: &BpfRawSection, event: &mut OvsEvent) -> Result<()> {
    let recirc = parse_raw_section::<OvsActionRecirc>(raw_section)?;
    update_action_event(event, OvsAction::Recirc(*recirc))
}

pub(super) fn unmarshall_ct(raw_section: &BpfRawSection, event: &mut OvsEvent) -> Result<()> {
    #[repr(C, packed)]
    union IP {
        ipv4: u32,
        ipv6: u128,
    }

    impl Default for IP {
        fn default() -> Self {
            IP { ipv6: 0 }
        }
    }

    #[raw_event_section]
    struct BpfConntrackAction {
        flags: u32,
        zone_id: u16,
        min_addr: IP,
        max_addr: IP,
        min_port: u16,
        max_port: u16,
    }

    let raw = parse_raw_section::<BpfConntrackAction>(raw_section)?;
    let nat = if raw.flags & R_OVS_CT_NAT != 0 {
        let flags = raw.flags;
        let dir = match flags {
            f if f & R_OVS_CT_NAT_SRC != 0 => Some(NatDirection::Src),
            f if f & R_OVS_CT_NAT_DST != 0 => Some(NatDirection::Dst),
            _ => None,
        };

        let (min_addr, max_addr) = if raw.flags & R_OVS_CT_NAT_RANGE_MAP_IPS != 0 {
            if raw.flags & R_OVS_CT_IP4 != 0 {
                let min_addr = unsafe { raw.min_addr.ipv4 };
                let max_addr = unsafe { raw.max_addr.ipv4 };
                (
                    Some(helpers::net::parse_ipv4_addr(u32::from_be(min_addr))?),
                    Some(helpers::net::parse_ipv4_addr(u32::from_be(max_addr))?),
                )
            } else if raw.flags & R_OVS_CT_IP6 != 0 {
                let min_addr = unsafe { raw.min_addr.ipv6 };
                let max_addr = unsafe { raw.max_addr.ipv6 };
                (
                    Some(Ipv6Addr::from(u128::from_be(min_addr)).to_string()),
                    Some(Ipv6Addr::from(u128::from_be(max_addr)).to_string()),
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
    update_action_event(event, OvsAction::Ct(ct))
}

pub(super) fn unmarshall_recv(raw_section: &BpfRawSection) -> Result<OvsEvent> {
    let recv = parse_raw_section::<RecvUpcallEvent>(raw_section)?;
    Ok(OvsEvent {
        event: OvsEventType::RecvUpcall(*recv),
    })
}

pub(super) fn unmarshall_operation(raw_section: &BpfRawSection) -> Result<OvsEvent> {
    let op = parse_raw_section::<OperationEvent>(raw_section)?;

    Ok(OvsEvent {
        event: OvsEventType::Operation(*op),
    })
}

pub(super) fn unmarshall_upcall_enqueue(raw_section: &BpfRawSection) -> Result<OvsEvent> {
    let enqueue = parse_raw_section::<UpcallEnqueueEvent>(raw_section)?;

    Ok(OvsEvent {
        event: OvsEventType::UpcallEnqueue(*enqueue),
    })
}

pub(super) fn unmarshall_upcall_return(raw_section: &BpfRawSection) -> Result<OvsEvent> {
    let uret = parse_raw_section::<UpcallReturnEvent>(raw_section)?;

    Ok(OvsEvent {
        event: OvsEventType::UpcallReturn(*uret),
    })
}

#[event_section_factory(FactoryId::Ovs)]
#[derive(Default)]
pub(crate) struct OvsEventFactory {}

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
                    event = Some(unmarshall_exec(section)?);
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

    impl RawSectionBuilder for BpfActionEvent {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = BpfActionEvent {
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
