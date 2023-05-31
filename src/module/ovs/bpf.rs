//! Rust<>BPF types definitions for the ovs module.
//! Please keep this file in sync with its BPF counterpart in bpf/.

use anyhow::{bail, Result};
use plain::Plain;

use super::event::*;
use crate::core::events::bpf::{parse_raw_section, BpfRawSection};

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
    event.event = OvsEventType::Upcall(upcall);
    Ok(())
}

/// OVS action event data.
#[derive(Default)]
#[repr(C)]
struct BpfActionEvent {
    /// Action to be executed.
    action: u8,
    /// Recirculation id.
    recirc_id: u32,
}

unsafe impl Plain for BpfActionEvent {}

pub(super) fn unmarshall_exec(raw_section: &BpfRawSection, event: &mut OvsEvent) -> Result<()> {
    let raw = parse_raw_section::<BpfActionEvent>(raw_section)?;

    // Any of the action-related bpf events (e.g BpfActionTrackEvent, BpfActionTrackEvent, etc)
    // might have been received before. If so, event.event is already a valid
    // OvsEventType::Action.
    match &event.event {
        OvsEventType::Action(mut action) => {
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
                    7 => OvsAction::Recirc,
                    8 => OvsAction::Hash,
                    9 => OvsAction::PushMpls,
                    10 => OvsAction::PopMpls,
                    11 => OvsAction::SetMasked,
                    12 => OvsAction::Ct,
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
#[derive(Default)]
#[repr(C)]
struct BpfActionTrackEvent {
    /// Queue id.
    queue_id: u32,
}

unsafe impl Plain for BpfActionTrackEvent {}

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

/// OVS output action data.
#[derive(Default)]
#[repr(C)]
struct BpfOvsActionOutput {
    /// Output port.
    port: u32,
}
unsafe impl Plain for BpfOvsActionOutput {}

pub(super) fn unmarshall_output(raw_section: &BpfRawSection, event: &mut OvsEvent) -> Result<()> {
    let raw = parse_raw_section::<BpfOvsActionOutput>(raw_section)?;
    let output = OvsActionOutput { port: raw.port };

    // Any of the action-related bpf events (e.g BpfActionEvent, BpfActionTrackEvent, etc)
    // might have been received before. If so, event.event is already a valid
    // OvsEventType::Action.
    match &mut event.event {
        OvsEventType::Action(ref mut action) => action.action = OvsAction::Output(output),
        OvsEventType::Undefined => {
            // We received the concrete action data type before the generic one.
            // Initialize the Action Event.
            event.event = OvsEventType::Action(ActionEvent {
                action: OvsAction::Output(output),
                ..ActionEvent::default()
            });
        }
        other => {
            bail!(
                "Conflicting OVS event types. Received {:?} data type but event is already {:#?}",
                OvsDataType::OutputAction,
                other
            );
        }
    }
    Ok(())
}

pub(super) fn unmarshall_recv(raw_section: &BpfRawSection, event: &mut OvsEvent) -> Result<()> {
    ensure_undefined(event, OvsDataType::RecvUpcall)?;
    let recv = parse_raw_section::<RecvUpcallEvent>(raw_section)?;
    event.event = OvsEventType::RecvUpcall(recv);

    Ok(())
}

pub(super) fn unmarshall_operation(
    raw_section: &BpfRawSection,
    event: &mut OvsEvent,
) -> Result<()> {
    ensure_undefined(event, OvsDataType::Operation)?;
    let op = parse_raw_section::<OperationEvent>(raw_section)?;

    event.event = OvsEventType::Operation(op);
    Ok(())
}

pub(super) fn unmarshall_upcall_enqueue(
    raw_section: &BpfRawSection,
    event: &mut OvsEvent,
) -> Result<()> {
    ensure_undefined(event, OvsDataType::UpcallEnqueue)?;
    let enqueue = parse_raw_section::<UpcallEnqueueEvent>(raw_section)?;

    event.event = OvsEventType::UpcallEnqueue(enqueue);
    Ok(())
}

pub(super) fn unmarshall_upcall_return(
    raw_section: &BpfRawSection,
    event: &mut OvsEvent,
) -> Result<()> {
    ensure_undefined(event, OvsDataType::UpcallReturn)?;
    let uret = parse_raw_section::<UpcallReturnEvent>(raw_section)?;

    event.event = OvsEventType::UpcallReturn(uret);
    Ok(())
}
