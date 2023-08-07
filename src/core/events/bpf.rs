//! Handles the BPF to Rust event retrieval and the unmarshaling process.

#![cfg_attr(test, allow(dead_code))]
#![cfg_attr(test, allow(unused_imports))]

use std::{
    collections::HashMap,
    fmt, mem,
    os::fd::{AsFd, AsRawFd, RawFd},
    sync::mpsc,
    thread,
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use log::error;
use plain::Plain;

use super::{Event, EventResult};
use crate::{
    core::events::*, core::signals::Running, event_section, event_section_factory, module::ModuleId,
};

/// Raw event sections for common.
pub(super) const COMMON_SECTION_CORE: u64 = 0;
pub(super) const COMMON_SECTION_TASK: u64 = 1;

/// Timeout when polling for new events from BPF.
const BPF_EVENTS_POLL_TIMEOUT_MS: u64 = 200;

/// Macro that define Default-able fixed size sequence of bytes aimed
/// to contain zero-terminated strings. Useful for unmarshaling array
/// of characters bigger than 32 elements.
#[macro_export]
macro_rules! event_byte_array {
    ($name:ident, $size:expr) => {
        struct $name([u8; $size]);

        impl Default for $name {
            fn default() -> Self {
                // Safety is respected as the type is well defined and
                // controlled.
                unsafe { std::mem::zeroed() }
            }
        }

        #[allow(dead_code)]
        impl $name {
            fn to_string(&self) -> Result<String> {
                Ok(std::str::from_utf8(&self.0)?
                    .trim_end_matches(char::from(0))
                    .into())
            }

            fn to_string_opt(&self) -> Result<Option<String>> {
                let res = self.to_string()?;

                if res.is_empty() {
                    return Ok(None);
                }

                Ok(Some(res))
            }
        }
    };
}

/// BPF events factory retrieving and unmarshaling events coming from the BPF
/// parts.
#[cfg(not(test))]
pub(crate) struct BpfEventsFactory {
    map: libbpf_rs::MapHandle,
    /// Receiver channel to retrieve events from the processing loop.
    rxc: Option<mpsc::Receiver<Event>>,
    /// Polling thread handle.
    handle: Option<thread::JoinHandle<()>>,
    run_state: Running,
}

#[cfg(not(test))]
impl BpfEventsFactory {
    pub(crate) fn new() -> Result<BpfEventsFactory> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        let map = libbpf_rs::MapHandle::create(
            libbpf_rs::MapType::RingBuf,
            Some("events_map"),
            0,
            0,
            mem::size_of::<RawEvent>() as u32 * BPF_EVENTS_MAX,
            &opts,
        )
        .or_else(|e| bail!("Failed to create events map: {}", e))?;

        Ok(BpfEventsFactory {
            map,
            rxc: None,
            handle: None,
            run_state: Running::new(),
        })
    }

    /// Get the events map fd for reuse.
    pub(crate) fn map_fd(&self) -> RawFd {
        self.map.as_fd().as_raw_fd()
    }
}

#[cfg(not(test))]
impl EventFactory for BpfEventsFactory {
    /// This starts the event polling mechanism. A dedicated thread is started
    /// for events to be retrieved and processed.
    fn start(&mut self, mut section_factories: SectionFactories) -> Result<()> {
        if section_factories.is_empty() {
            bail!("No section factory, can't parse events, aborting");
        }

        // Create the sending and receiving channels.
        let (txc, rxc) = mpsc::channel();
        self.rxc = Some(rxc);

        let run_state = self.run_state.clone();
        // Closure to handle the raw events coming from the BPF part.
        let process_event = move |data: &[u8]| -> i32 {
            // If a termination signal got received, return (EINTR)
            // from the callback in order to trigger the event thread
            // termination. This is useful in the case we're
            // processing a huge number of buffers and rb.poll() never
            // times out.
            if !run_state.running() {
                return -4;
            }
            // Parse the raw event.
            let event = match parse_raw_event(data, &mut section_factories) {
                Ok(event) => event,
                Err(e) => {
                    error!("Could not parse raw event: {}", e);
                    return 0;
                }
            };

            // Send the event into the events channel for future retrieval.
            if let Err(e) = txc.send(event) {
                error!("Could not send event: {}", e);
            }

            0
        };

        // Finally make our ring buffer and associate our map to our event
        // processing closure.
        let mut rb = libbpf_rs::RingBufferBuilder::new();
        rb.add(&self.map, process_event)?;
        let rb = rb.build()?;
        let rs = self.run_state.clone();
        // Start an event polling thread.
        self.handle = Some(thread::spawn(move || {
            while rs.running() {
                if let Err(e) = rb.poll(Duration::from_millis(BPF_EVENTS_POLL_TIMEOUT_MS)) {
                    match e {
                        // Received EINTR while polling the
                        // ringbuffer. This could normally be
                        // triggered by an actual interruption
                        // (signal) or artificially from the
                        // callback. Exit without printing any error.
                        libbpf_rs::Error::System(4) => (),
                        _ => error!("Unexpected error while polling ({e})"),
                    }
                    break;
                }
            }
        }));

        Ok(())
    }

    /// Stops the event polling mechanism. The dedicated thread is stopped
    /// joining the execution
    fn stop(&mut self) -> Result<()> {
        match self.handle.take() {
            Some(th) => {
                self.run_state.terminate();
                th.join()
                    .or_else(|_| bail!("while joining bpf event thread"))
            }
            None => Ok(()),
        }
    }

    /// Retrieve the next event. This is a blocking call and never returns EOF.
    fn next_event(&mut self, timeout: Option<Duration>) -> Result<EventResult> {
        let rxc = match &self.rxc {
            Some(rxc) => rxc,
            None => bail!("Can't get event, no rx channel found."),
        };

        Ok(match timeout {
            Some(timeout) => match rxc.recv_timeout(timeout) {
                Ok(event) => EventResult::Event(event),
                Err(mpsc::RecvTimeoutError::Timeout) => EventResult::Timeout,
                Err(e) => return Err(anyhow!(e)),
            },
            None => EventResult::Event(rxc.recv()?),
        })
    }
}

pub(crate) fn parse_raw_event<'a>(
    data: &'a [u8],
    factories: &'a mut SectionFactories,
) -> Result<Event> {
    // First retrieve the buffer length.
    let data_size = data.len();
    if data_size < 2 {
        bail!("Raw event is too small, can't retrieve its size");
    }

    // Then retrieve the raw event full size. Use unwrap below as we
    // know the [..2] bytes are valid and can be converted to [u8; 2].
    let raw_event_size = u16::from_ne_bytes(data[..2].try_into().unwrap()) as usize;
    if raw_event_size == 0 {
        bail!("Raw event is empty");
    }

    // Add sizeof(u16) to the raw event size to take into account the
    // event size field.
    let raw_event_size = raw_event_size + mem::size_of::<u16>();

    // Check the total buffer length to ensure we'll not go past.
    if raw_event_size > data_size {
        bail!(
            "Raw event size goes past the buffer length: {} > {}",
            raw_event_size,
            data_size
        );
    }

    // Let's loop through the raw event sections and collect them for later
    // processing. Cursor is initialized to sizeof(u16) as we already read the
    // raw event size above.
    let mut cursor = 2;
    let mut raw_sections = HashMap::new();
    while cursor < raw_event_size {
        // Get the current raw section header.
        let mut raw_section = BpfRawSection::default();
        if plain::copy_from_bytes(&mut raw_section.header, &data[cursor..]).is_err() {
            error!("Can't read raw section header, it goes past the buffer end");
            break;
        }
        cursor += mem::size_of_val(&raw_section.header);

        // Compute where the current section ends.
        let raw_section_end = cursor + raw_section.header.size as usize;

        // First check the header is valid and check we're not going
        // past the buffer length.
        if raw_section.header.size == 0 {
            error!("Section is empty, according to its header");
            continue;
        } else if raw_section_end > raw_event_size {
            error!(
                "Section goes past the buffer: {} > {}",
                raw_section_end, raw_event_size
            );
            break;
        }

        // Try converting the raw owner id into something we can use.
        let owner = match ModuleId::from_u8(raw_section.header.owner) {
            Ok(owner) => owner,
            Err(e) => {
                // Skip the section.
                cursor += raw_section.header.size as usize;
                error!("Could not convert the raw owner: {}", e);
                continue;
            }
        };

        // Get the raw data.
        raw_section.data = data[cursor..raw_section_end].to_vec();
        cursor += raw_section.header.size as usize;

        // Save the raw section for later processing.
        raw_sections
            .entry(owner)
            .or_insert(Vec::new())
            .push(raw_section);
    }

    let mut event = Event::new();
    raw_sections.drain().try_for_each(|(owner, sections)| {
        let factory = match factories.get_mut(&owner) {
            Some(factory) => factory,
            None => bail!("Unknown factory for event section owner {}", owner),
        };
        event.insert_section(owner, factory.from_raw(sections)?)
    })?;

    Ok(event)
}

/// Helper to check a raw section validity and parse it into a structured type.
pub(crate) fn parse_raw_section<T>(raw_section: &BpfRawSection) -> Result<T>
where
    T: Default + Plain,
{
    if raw_section.data.len() != mem::size_of::<T>() {
        bail!("Section data is not the expected size");
    }

    let mut event = T::default();
    plain::copy_from_bytes(&mut event, &raw_section.data)
        .or_else(|_| bail!("Could not parse the raw section"))?;

    Ok(event)
}

/// Helper to parse a single raw section from BPF raw sections, checking the
/// section validity and parsing it into a structured type.
pub(crate) fn parse_single_raw_section<T>(
    id: ModuleId,
    mut raw_sections: Vec<BpfRawSection>,
) -> Result<T>
where
    T: Default + Plain,
{
    if raw_sections.len() != 1 {
        bail!("{id} event from BPF must be a single section");
    }

    // Unwrap as we just checked the vector contains 1 element.
    parse_raw_section::<T>(&raw_sections.pop().unwrap())
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
pub(crate) struct TaskEvent {
    /// Process id.
    pub(crate) pid: i32,
    /// Thread group id.
    pub(crate) tgid: i32,
    /// Name of the current task.
    pub(crate) comm: String,
}

#[event_section]
pub(crate) struct CommonEvent {
    /// Timestamp of when the event was generated.
    pub(crate) timestamp: u64,
    pub(crate) task: Option<TaskEvent>,
}

impl EventFmt for CommonEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        write!(f, "{}", self.timestamp)?;

        if let Some(current) = &self.task {
            write!(f, " [{}] ", current.comm)?;
            if current.tgid != current.pid {
                write!(f, "{}/", current.pid)?;
            }
            write!(f, "{}", current.tgid)?;
        }

        Ok(())
    }
}

#[derive(Default)]
#[event_section_factory(CommonEvent)]
pub(crate) struct CommonEventFactory {}

impl RawEventSectionFactory for CommonEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut common = CommonEvent::default();

        for section in raw_sections.iter() {
            match section.header.data_type as u64 {
                COMMON_SECTION_CORE => common.timestamp = parse_raw_section::<u64>(section)?,
                COMMON_SECTION_TASK => common.task = Some(unmarshal_task(section)?),
                _ => bail!("Unknown data type"),
            }
        }

        Ok(Box::new(common))
    }
}

event_byte_array!(TaskName, 64);

/// Task information retrieved in common probes.
#[derive(Default)]
#[repr(C)]
struct RawTaskEvent {
    /// pid/tgid.
    pid: u64,
    /// Current task name.
    comm: TaskName,
}
unsafe impl Plain for RawTaskEvent {}

pub(super) fn unmarshal_task(raw_section: &BpfRawSection) -> Result<TaskEvent> {
    let mut task_event = TaskEvent::default();
    let raw = parse_raw_section::<RawTaskEvent>(raw_section)?;

    (task_event.pid, task_event.tgid) = ((raw.pid & 0xFFFFFFFF) as i32, (raw.pid >> 32) as i32);
    task_event.comm = raw.comm.to_string()?;

    Ok(task_event)
}

// We use a dummy implementation of BpfEventsFactory to allow unit tests to pass.
// This is fine as no function in the above can really be tested.
#[cfg(test)]
pub(crate) struct BpfEventsFactory;
#[cfg(test)]
impl BpfEventsFactory {
    pub(crate) fn new() -> Result<BpfEventsFactory> {
        Ok(BpfEventsFactory {})
    }
    pub(crate) fn map_fd(&self) -> i32 {
        0
    }
}
#[cfg(test)]
impl EventFactory for BpfEventsFactory {
    fn start(&mut self, _: SectionFactories) -> Result<()> {
        Ok(())
    }
    fn next_event(&mut self, _: Option<Duration>) -> Result<EventResult> {
        Ok(EventResult::Event(Event::new()))
    }
    fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Max number of events we can store at once in the shared map. Please keep in
/// sync with its BPF counterpart.
pub(super) const BPF_EVENTS_MAX: u32 = 8 * 1024;

/// Size of the raw data buffer of a BPF event. Please keep synced with its BPF
/// counterpart.
pub(super) const BPF_RAW_EVENT_DATA_SIZE: usize = 1024 - 2 /* remove the size field */;

/// Raw event format shared between the Rust and BPF part. Please keep in sync
/// with its BPF counterpart.
#[repr(C, packed)]
pub(super) struct RawEvent {
    size: u16,
    data: [u8; BPF_RAW_EVENT_DATA_SIZE],
}

unsafe impl Plain for RawEvent {}

/// Raw event section format shared between the Rust and BPF part. Please keep
/// in sync with its BPF counterpart.
#[derive(Clone, Default)]
pub(crate) struct BpfRawSection {
    pub(crate) header: BpfRawSectionHeader,
    pub(crate) data: Vec<u8>,
}

/// Raw event section header shared between the Rust and BPF part. Please keep
/// in sync with its BPF counterpart.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub(crate) struct BpfRawSectionHeader {
    pub(super) owner: u8,
    pub(crate) data_type: u8,
    pub(crate) size: u16,
}

unsafe impl Plain for BpfRawSectionHeader {}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::{EventSection, EventSectionFactory};

    const DATA_TYPE_U64: u8 = 1;
    const DATA_TYPE_U128: u8 = 2;

    #[derive(Default, Deserialize, Serialize, EventSection, EventSectionFactory)]
    struct TestEvent {
        field0: Option<u64>,
        field1: Option<u64>,
        field2: Option<u64>,
    }

    impl EventFmt for TestEvent {
        fn event_fmt(&self, f: &mut std::fmt::Formatter, _: DisplayFormat) -> std::fmt::Result {
            write!(
                f,
                "field0: {:?} field1: {:?} field2: {:?}",
                self.field0, self.field1, self.field2
            )
        }
    }

    impl RawEventSectionFactory for TestEvent {
        fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
            let mut event = TestEvent::default();

            for raw in raw_sections.iter() {
                let len = raw.data.len();

                match raw.header.data_type {
                    DATA_TYPE_U64 => {
                        if len != 8 {
                            bail!("Invalid section for data type 1");
                        }

                        event.field0 = Some(u64::from_ne_bytes(raw.data[0..8].try_into()?));
                    }
                    DATA_TYPE_U128 => {
                        if len != 16 {
                            bail!("Invalid section for data type 2");
                        }

                        event.field1 = Some(u64::from_ne_bytes(raw.data[0..8].try_into()?));
                        event.field2 = Some(u64::from_ne_bytes(raw.data[8..16].try_into()?));
                    }
                    _ => bail!("Invalid data type"),
                }
            }

            Ok(Box::new(event))
        }
    }

    #[test]
    fn parse_raw_event() {
        let mut factories: SectionFactories = HashMap::new();
        factories.insert(ModuleId::Common, Box::<TestEvent>::default());

        // Empty event.
        let data = [];
        assert!(super::parse_raw_event(&data, &mut factories).is_err());

        // Uncomplete event size.
        let data = [0];
        assert!(super::parse_raw_event(&data, &mut factories).is_err());

        // Valid event size but empty event.
        let data = [0, 0];
        assert!(super::parse_raw_event(&data, &mut factories).is_err());

        // Valid event size but incomplete event.
        let data = [42, 0];
        assert!(super::parse_raw_event(&data, &mut factories).is_err());
        let data = [2, 0, 42];
        assert!(super::parse_raw_event(&data, &mut factories).is_err());

        // Valid event with a single empty section. Section is ignored.
        let data = [4, 0, ModuleId::Common as u8, DATA_TYPE_U64, 0, 0];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());

        // Valid event with a section too large. Section is ignored.
        let data = [4, 0, ModuleId::Common as u8, DATA_TYPE_U64, 4, 0, 42, 42];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());
        let data = [6, 0, ModuleId::Common as u8, DATA_TYPE_U64, 4, 0, 42, 42];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());

        // Valid event with a section having an invalid owner.
        let data = [4, 0, 0, DATA_TYPE_U64, 0, 0];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());
        let data = [4, 0, 255, DATA_TYPE_U64, 0, 0];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());

        // Valid event with an invalid data type.
        let data = [4, 0, ModuleId::Common as u8, 0, 1, 0, 42];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());
        let data = [4, 0, ModuleId::Common as u8, 255, 1, 0, 42];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());

        // Valid event but invalid section (too small).
        let data = [5, 0, ModuleId::Common as u8, DATA_TYPE_U64, 1, 0, 42];
        assert!(super::parse_raw_event(&data, &mut factories).is_err());

        // Valid event, single section.
        let data = [
            12,
            0,
            ModuleId::Common as u8,
            DATA_TYPE_U64,
            8,
            0,
            42,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let event = super::parse_raw_event(&data, &mut factories).unwrap();
        let section = event.get_section::<TestEvent>(ModuleId::Common).unwrap();
        assert!(section.field0 == Some(42));

        // Valid event, multiple sections.
        let data = [
            44,
            0,
            // Section 1
            ModuleId::Common as u8,
            DATA_TYPE_U64,
            8,
            0,
            42,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // Section 2
            ModuleId::Common as u8,
            DATA_TYPE_U64,
            8,
            0,
            57,
            5,
            0,
            0,
            0,
            0,
            0,
            0,
            // Section 3
            ModuleId::Common as u8,
            DATA_TYPE_U128,
            16,
            0,
            42,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            57,
            5,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let event = super::parse_raw_event(&data, &mut factories).unwrap();
        let section = event.get_section::<TestEvent>(ModuleId::Common).unwrap();
        assert!(section.field1 == Some(42));
        assert!(section.field2 == Some(1337));
    }
}
