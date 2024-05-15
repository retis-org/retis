//! Rust<>BPF types definitions for the ovs module.
//! Please keep this file in sync with its BPF counterpart in bpf/.

use std::net::Ipv6Addr;

use anyhow::{bail, Result};

use crate::{
    core::events::{parse_raw_section, BpfRawSection, EventSectionFactory, RawEventSectionFactory},
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

// OVS module supports several event data types but many of them end up setting the OvsEvent
// to one of its variants which mean they are mutally exclusive.
// This helper ensures the event has was not set before to any of its variants to help
// report his error condition.
pub(crate) fn ensure_undefined(event: &OvsEvent, received: OvsDataType) -> Result<()> {
    match &event.event {
        OvsEventType::Undefined => Ok(()),
        other => bail!(
            "Conflicting OVS event types. Received {:?} data type but event is already {:#?}",
            received,
            other
        ),
    }
}

pub(super) fn unmarshall_upcall(raw_section: &BpfRawSection, event: &mut OvsEvent) -> Result<()> {
    ensure_undefined(event, OvsDataType::Upcall)?;
    let upcall = parse_raw_section::<UpcallEvent>(raw_section)?;
    event.event = OvsEventType::Upcall(*upcall);
    Ok(())
}

/// OVS action event data.
#[repr(C)]
struct BpfActionEvent {
    /// Action to be executed.
    action: u8,
    /// Recirculation id.
    recirc_id: u32,
}

pub(super) fn unmarshall_exec(raw_section: &BpfRawSection, event: &mut OvsEvent) -> Result<()> {
    let raw = parse_raw_section::<BpfActionEvent>(raw_section)?;

    // Any of the action-related bpf events (e.g BpfActionTrackEvent, BpfActionTrackEvent, etc)
    // might have been received before. If so, event.event is already a valid
    // OvsEventType::Action.
    match &mut event.event {
        OvsEventType::Action(action) => {
            // One of the specific action events has already been received and it has initialized
            // the action.data enum. Only the common data has to be set here.
            action.recirc_id = raw.recirc_id;
        }
        OvsEventType::Undefined => {
            // When we implement event data types for every action we will be able to create the
            // specific action variant when unmarshaling its event data type. Until then, we need to
            // initialize the Action here based on the action_id (which corresponds to ovs_action_attr
            // defined in uapi/linux/openvswitch.h).
            event.event = OvsEventType::Action(ActionEvent {
                action: match raw.action {
                    0 => OvsAction::Unspecified,
                    1 => OvsAction::Output(OvsActionOutput::default()),
                    2 => OvsAction::Userspace,
                    3 => OvsAction::Set,
                    4 => OvsAction::PushVlan,
                    5 => OvsAction::PopVlan,
                    6 => OvsAction::Sample,
                    7 => OvsAction::Recirc(OvsActionRecirc::default()),
                    8 => OvsAction::Hash,
                    9 => OvsAction::PushMpls,
                    10 => OvsAction::PopMpls,
                    11 => OvsAction::SetMasked,
                    12 => OvsAction::Ct(OvsActionCt::default()),
                    13 => OvsAction::Trunc,
                    14 => OvsAction::PushEth,
                    15 => OvsAction::PopEth,
                    16 => OvsAction::CtClear,
                    17 => OvsAction::PushNsh,
                    18 => OvsAction::PopNsh,
                    19 => OvsAction::Meter,
                    20 => OvsAction::Clone,
                    21 => OvsAction::CheckPktLen,
                    22 => OvsAction::AddMpls,
                    23 => OvsAction::DecTtl,
                    // The private OVS_ACTION_ATTR_SET_TO_MASKED action is used
                    // in the same way as OVS_ACTION_ATTR_SET_MASKED. Use only
                    // one action to avoid confusion
                    25 => OvsAction::SetMasked,
                    val => bail!("Unsupported action id {val}"),
                },
                recirc_id: raw.recirc_id,
                ..ActionEvent::default()
            });
        }
        other => {
            bail!(
                "Conflicting OVS event types. Received {:?} data type but event is already {:#?}",
                OvsDataType::ActionExec,
                other
            );
        }
    }
    Ok(())
}

/// OVS action tracking event data.
#[repr(C)]
struct BpfActionTrackEvent {
    /// Queue id.
    queue_id: u32,
}

pub(super) fn unmarshall_exec_track(
    raw_section: &BpfRawSection,
    event: &mut OvsEvent,
) -> Result<()> {
    let raw = parse_raw_section::<BpfActionTrackEvent>(raw_section)?;

    // Any of the action-related bpf events (e.g BpfActionEvent, BpfActionTrackEvent, etc)
    // might have been received before. If so, event.event is already a valid
    // OvsEventType::Action.
    match &mut event.event {
        OvsEventType::Action(ref mut action) => action.queue_id = Some(raw.queue_id),
        OvsEventType::Undefined => {
            // We received the tracking event before the generic one.
            // Initialize the Action Event.
            event.event = OvsEventType::Action(ActionEvent {
                queue_id: Some(raw.queue_id),
                ..ActionEvent::default()
            });
        }
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
    // Any of the action-related bpf events (e.g BpfActionEvent, BpfActionTrackEvent, etc)
    // might have been received before. If so, event.event is already a valid
    // OvsEventType::Action.
    match &mut event.event {
        OvsEventType::Action(ref mut event) => event.action = action,
        OvsEventType::Undefined => {
            // We received the concrete action data type before the generic one.
            // Initialize the Action Event.
            event.event = OvsEventType::Action(ActionEvent {
                action,
                ..ActionEvent::default()
            });
        }
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
    #[repr(C)]
    union IP {
        ipv4: u32,
        ipv6: u128,
    }

    #[repr(C, packed)]
    struct BpfConntrackAction {
        flags: u32,
        zone_id: u16,
        min_addr: IP,
        max_addr: IP,
        min_port: u16,
        max_port: u16,
    }

    impl Default for BpfConntrackAction {
        fn default() -> Self {
            BpfConntrackAction {
                flags: 0,
                zone_id: 0,
                min_addr: IP { ipv6: 0 },
                max_addr: IP { ipv6: 0 },
                min_port: 0,
                max_port: 0,
            }
        }
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

pub(super) fn unmarshall_recv(raw_section: &BpfRawSection, event: &mut OvsEvent) -> Result<()> {
    ensure_undefined(event, OvsDataType::RecvUpcall)?;
    let recv = parse_raw_section::<RecvUpcallEvent>(raw_section)?;
    event.event = OvsEventType::RecvUpcall(*recv);

    Ok(())
}

pub(super) fn unmarshall_operation(
    raw_section: &BpfRawSection,
    event: &mut OvsEvent,
) -> Result<()> {
    ensure_undefined(event, OvsDataType::Operation)?;
    let op = parse_raw_section::<OperationEvent>(raw_section)?;

    event.event = OvsEventType::Operation(*op);
    Ok(())
}

pub(super) fn unmarshall_upcall_enqueue(
    raw_section: &BpfRawSection,
    event: &mut OvsEvent,
) -> Result<()> {
    ensure_undefined(event, OvsDataType::UpcallEnqueue)?;
    let enqueue = parse_raw_section::<UpcallEnqueueEvent>(raw_section)?;

    event.event = OvsEventType::UpcallEnqueue(*enqueue);
    Ok(())
}

pub(super) fn unmarshall_upcall_return(
    raw_section: &BpfRawSection,
    event: &mut OvsEvent,
) -> Result<()> {
    ensure_undefined(event, OvsDataType::UpcallReturn)?;
    let uret = parse_raw_section::<UpcallReturnEvent>(raw_section)?;

    event.event = OvsEventType::UpcallReturn(*uret);
    Ok(())
}

#[derive(Default, crate::EventSectionFactory)]
pub(crate) struct OvsEventFactory {}

impl RawEventSectionFactory for OvsEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
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
