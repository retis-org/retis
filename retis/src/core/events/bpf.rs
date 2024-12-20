//! Handles the BPF to Rust event retrieval and the unmarshaling process.

#![cfg_attr(test, allow(dead_code))]
#![cfg_attr(test, allow(unused_imports))]

use std::{
    any,
    collections::HashMap,
    mem,
    os::fd::{AsFd, AsRawFd, RawFd},
    sync::mpsc,
    thread,
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use btf_rs::Type;
use log::{error, log, Level};
use plain::Plain;

use crate::{
    bindings::events_uapi::*, core::inspect::inspector, event_section_factory, events::*,
    helpers::signals::Running,
};

/// Raw event sections for common.
pub(super) const COMMON_SECTION_CORE: u64 = 0;
pub(super) const COMMON_SECTION_TASK: u64 = 1;

/// Timeout when polling for new events from BPF.
const BPF_EVENTS_POLL_TIMEOUT_MS: u64 = 200;

/// Macro used to convert c_char into String.
/// The macro returns error if the conversion fails.
#[macro_export]
macro_rules! raw_to_string {
    ($c_array:expr) => {{
        use anyhow::{anyhow, Result};
        use std::{ffi::CStr, os::raw::c_char};

        let to_string = |arr: &[c_char]| -> Result<String> {
            let _null_pos = arr
                .iter()
                .position(|&c| c == 0)
                .ok_or_else(|| anyhow!("String is not NULL terminated"))?;

            let cstr = unsafe { CStr::from_ptr(arr.as_ptr()) };
            Ok(cstr.to_string_lossy().into_owned())
        };

        to_string($c_array)
    }};
}

/// A macro for converting a `c_char` array into a `String`.  It
/// returns an error in case of failure. Upon successful conversion,
/// it checks if the resulting `String` is empty, returning `Ok(None)`
/// if it is.
#[macro_export]
macro_rules! raw_to_string_opt {
    ($c_array:expr) => {{
        use anyhow::Result;
        use std::os::raw::c_char;
        let to_string_opt = |arr: &[c_char]| -> Result<Option<String>> {
            let res = raw_to_string!(arr)?;

            if res.is_empty() {
                return Ok(None);
            }

            Ok(Some(res))
        };

        to_string_opt($c_array)
    }};
}

/// The return value of EventFactory::next_event()
pub(crate) enum EventResult {
    /// The Factory was able to create a new event.
    Event(Event),
    /// The timeout went off but a new attempt to retrieve an event might succeed.
    Timeout,
}

/// BPF events factory retrieving and unmarshaling events coming from the BPF
/// parts.
#[cfg(not(test))]
pub(crate) struct BpfEventsFactory {
    map: libbpf_rs::MapHandle,
    log_map: libbpf_rs::MapHandle,
    /// Receiver channel to retrieve events from the processing loop.
    rxc: Option<mpsc::Receiver<Event>>,
    /// Polling thread handle.
    handle: Option<thread::JoinHandle<()>>,
    log_handle: Option<thread::JoinHandle<()>>,
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

        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };
        let log_map = libbpf_rs::MapHandle::create(
            libbpf_rs::MapType::RingBuf,
            Some("log_map"),
            0,
            0,
            mem::size_of::<retis_log_event>() as u32 * LOG_EVENTS_MAX,
            &opts,
        )
        .or_else(|e| bail!("Failed to create log map: {}", e))?;

        Ok(BpfEventsFactory {
            map,
            log_map,
            rxc: None,
            handle: None,
            log_handle: None,
            run_state: Running::new(),
        })
    }

    /// Get the events map fd for reuse.
    pub(crate) fn map_fd(&self) -> RawFd {
        self.map.as_fd().as_raw_fd()
    }

    /// Get the log map fd for reuse.
    pub(crate) fn log_map_fd(&self) -> RawFd {
        self.log_map.as_fd().as_raw_fd()
    }

    fn ringbuf_handler<CB>(
        &self,
        map: &libbpf_rs::MapHandle,
        rb_handler: CB,
    ) -> Result<thread::JoinHandle<()>>
    where
        CB: FnMut(&[u8]) -> i32 + 'static,
    {
        let mut rb = libbpf_rs::RingBufferBuilder::new();
        rb.add(map, rb_handler)?;
        let rb = rb.build()?;
        let rs = self.run_state.clone();
        // Start an event polling thread.
        Ok(thread::spawn(move || {
            while rs.running() {
                if let Err(e) = rb.poll(Duration::from_millis(BPF_EVENTS_POLL_TIMEOUT_MS)) {
                    match e.kind() {
                        // Received EINTR while polling the
                        // ringbuffer. This could normally be
                        // triggered by an actual interruption
                        // (signal) or artificially from the
                        // callback. Do not print any error.
                        libbpf_rs::ErrorKind::Interrupted => (),
                        _ => error!("Unexpected error while polling ({e})"),
                    }
                }
            }
        }))
    }
}

#[cfg(not(test))]
impl BpfEventsFactory {
    /// This starts the event polling mechanism. A dedicated thread is started
    /// for events to be retrieved and processed.
    pub(crate) fn start(&mut self, mut section_factories: SectionFactories) -> Result<()> {
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

        let run_state = self.run_state.clone();
        // Closure to handle the log events coming from the BPF part.
        let process_log = move |data: &[u8]| -> i32 {
            if data.len() != mem::size_of::<retis_log_event>() {
                error!("Unexpected log event size");
                return 0;
            }
            // If a termination signal got received, return (EINTR)
            // from the callback in order to trigger the event thread
            // termination. This is useful in the case we're
            // processing a huge number of buffers and rb.poll() never
            // times out.
            if !run_state.running() {
                return -4;
            }

            let mut log_event = retis_log_event::default();
            if let Err(e) = plain::copy_from_bytes(&mut log_event, data) {
                error!("Can't read eBPF log event {:?}", e);
                return 0;
            }

            let log_level = match log_event.level {
                1 => Level::Error,
                2 => Level::Warn,
                3 => Level::Info,
                4 => Level::Debug,
                5 => Level::Trace,
                l => {
                    error!("Unexpected log level ({l}). Falling back to error level");
                    Level::Error
                }
            };

            match raw_to_string!(&log_event.msg) {
                Ok(msg) => log!(log_level, "[eBPF] {msg}"),
                Err(e) => error!("Unable to convert eBPF log string: {e}"),
            }

            0
        };

        // Finally make our ring buffers and associate maps to their
        // respective events processing closure.
        self.handle = Some(self.ringbuf_handler(&self.map, process_event)?);
        self.log_handle = Some(self.ringbuf_handler(&self.log_map, process_log)?);

        Ok(())
    }

    /// Stops the event polling mechanism. The dedicated thread is stopped
    /// joining the execution
    pub(crate) fn stop(&mut self) -> Result<()> {
        self.handle.take().map_or(Ok(()), |th| {
            self.run_state.terminate();
            th.join()
                .map_err(|_| anyhow!("while joining bpf event thread"))
        })?;

        self.log_handle.take().map_or(Ok(()), |th| {
            th.join()
                .map_err(|_| anyhow!("while joining bpf log event thread"))
        })
    }

    /// Retrieve the next event. This is a blocking call and never returns EOF.
    pub(crate) fn next_event(&mut self, timeout: Option<Duration>) -> Result<EventResult> {
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
        bail!("Raw event size goes past the buffer length: {raw_event_size} > {data_size}",);
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
            error!("Section goes past the buffer: {raw_section_end} > {raw_event_size}");
            break;
        }

        // Try converting the raw owner id into something we can use.
        let owner = match FactoryId::from_u8(raw_section.header.owner) {
            Ok(owner) => owner,
            Err(e) => {
                // Skip the section.
                cursor += raw_section.header.size as usize;
                error!("Could not convert the raw owner: {e}");
                continue;
            }
        };

        // Get the raw data.
        raw_section.data = &data[cursor..raw_section_end];
        cursor += raw_section.header.size as usize;

        // Save the raw section for later processing.
        raw_sections
            .entry(owner)
            .or_insert(Vec::new())
            .push(raw_section);
    }

    let mut event = Event::new();
    raw_sections.drain().try_for_each(|(owner, sections)| {
        let factory = factories
            .get_mut(&owner)
            .ok_or_else(|| anyhow!("Unknown factory {}", owner as u8))?;

        let section = factory
            .create(sections)
            .map_err(|e| anyhow!("Factory {} failed to parse section: {e}", owner as u8))?;
        event.insert_section(SectionId::from_u8(section.id())?, section)
    })?;

    Ok(event)
}

/// Helper to check a raw section validity and parse it into a structured type.
pub(crate) fn parse_raw_section<'a, T>(raw_section: &'a BpfRawSection) -> Result<&'a T> {
    if raw_section.data.len() != mem::size_of::<T>() {
        bail!(
            "Section data {} is not the expected size ({} != {})",
            any::type_name::<T>(),
            raw_section.data.len(),
            mem::size_of::<T>()
        );
    }

    Ok(unsafe { mem::transmute::<&u8, &T>(&raw_section.data[0]) })
}

/// Helper to parse a single raw section from BPF raw sections, checking the
/// section validity and parsing it into a structured type.
pub(crate) fn parse_single_raw_section<'a, T>(raw_sections: &'a [BpfRawSection]) -> Result<&'a T> {
    if raw_sections.len() != 1 {
        bail!("Raw event must be a single section");
    }

    // We can access the first element safely as we just checked the vector
    // contains 1 element.
    parse_raw_section::<T>(&raw_sections[0])
}

pub(crate) fn parse_enum(r#enum: &str, trim_start: &[&str]) -> Result<HashMap<u32, String>> {
    let mut values = HashMap::new();

    if let Ok(types) = inspector()?.kernel.btf.resolve_types_by_name(r#enum) {
        if let Some((btf, Type::Enum(r#enum))) =
            types.iter().find(|(_, t)| matches!(t, Type::Enum(_)))
        {
            for member in r#enum.members.iter() {
                let mut val = btf.resolve_name(member)?;
                trim_start
                    .iter()
                    .for_each(|p| val = val.trim_start_matches(p).to_string());
                values.insert(member.val(), val.to_string());
            }
        }
    }

    Ok(values)
}

#[event_section_factory(FactoryId::Common)]
#[derive(Default)]
pub(crate) struct CommonEventFactory {}

impl RawEventSectionFactory for CommonEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut common = CommonEvent::default();

        for section in raw_sections.iter() {
            match section.header.data_type as u64 {
                COMMON_SECTION_CORE => {
                    let raw = parse_raw_section::<common_event>(section)?;

                    common.timestamp = raw.timestamp;
                    common.smp_id = Some(raw.smp_id);
                }
                COMMON_SECTION_TASK => common.task = Some(unmarshal_task(section)?),
                _ => bail!("Unknown data type"),
            }
        }

        Ok(Box::new(common))
    }
}

pub(super) fn unmarshal_task(raw_section: &BpfRawSection) -> Result<TaskEvent> {
    let mut task_event = TaskEvent::default();
    let raw = parse_raw_section::<common_task_event>(raw_section)?;

    (task_event.tgid, task_event.pid) = ((raw.pid & 0xFFFFFFFF) as i32, (raw.pid >> 32) as i32);
    task_event.comm = raw_to_string!(&raw.comm)?;

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
impl BpfEventsFactory {
    pub(crate) fn start(&mut self, _: SectionFactories) -> Result<()> {
        Ok(())
    }
    pub(crate) fn next_event(&mut self, _: Option<Duration>) -> Result<EventResult> {
        Ok(EventResult::Event(Event::new()))
    }
    pub(crate) fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Max number of events we can store at once in the shared map. Please keep in
/// sync with its BPF counterpart.
pub(super) const BPF_EVENTS_MAX: u32 = 8 * 1024;

/// Size of the raw data buffer of a BPF event. Please keep synced with its BPF
/// counterpart.
pub(crate) const BPF_RAW_EVENT_DATA_SIZE: usize = 1024 - 2 /* remove the size field */;

/// Raw event format shared between the Rust and BPF part. Please keep in sync
/// with its BPF counterpart.
#[repr(C, packed)]
pub(crate) struct RawEvent {
    pub(crate) size: u16,
    pub(crate) data: [u8; BPF_RAW_EVENT_DATA_SIZE],
}

unsafe impl Plain for RawEvent {}

/// Raw event section format shared between the Rust and BPF part. Please keep
/// in sync with its BPF counterpart.
#[derive(Clone, Default)]
pub(crate) struct BpfRawSection<'a> {
    pub(crate) header: BpfRawSectionHeader,
    pub(crate) data: &'a [u8],
}

/// Raw event section header shared between the Rust and BPF part. Please keep
/// in sync with its BPF counterpart.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub(crate) struct BpfRawSectionHeader {
    pub(crate) owner: u8,
    pub(crate) data_type: u8,
    pub(crate) size: u16,
}

unsafe impl Plain for BpfRawSectionHeader {}

/// EventSection factory, providing helpers to create event sections from
/// ebpf.
///
/// Please use `#[retis_derive::event_section_factory]` to implement the common
/// traits.
pub(crate) trait EventSectionFactory: RawEventSectionFactory {
    #[allow(dead_code)]
    fn id(&self) -> u8;
    fn as_any_mut(&mut self) -> &mut dyn any::Any;
}

/// Event section factory helpers to convert from BPF raw events. Requires a
/// per-object implementation.
pub(crate) trait RawEventSectionFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>>;
}

/// Identifier for factories. Should match their counterparts in the BPF side.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum FactoryId {
    Common = 1,
    Kernel = 2,
    Userspace = 3,
    SkbTracking = 4,
    SkbDrop = 5,
    Skb = 6,
    Ovs = 7,
    Nft = 8,
    Ct = 9,
    // TODO: use std::mem::variant_count once in stable.
    _MAX = 10,
}

impl FactoryId {
    /// Constructs an FactoryId from a section unique identifier
    pub(crate) fn from_u8(val: u8) -> Result<Self> {
        use FactoryId::*;
        Ok(match val {
            1 => Common,
            2 => Kernel,
            3 => Userspace,
            4 => SkbTracking,
            5 => SkbDrop,
            6 => Skb,
            7 => Ovs,
            8 => Nft,
            9 => Ct,
            x => bail!("Can't construct a FactoryId from {}", x),
        })
    }
}

/// Type alias to refer to the commonly used EventSectionFactory HashMap.
pub(crate) type SectionFactories = HashMap<FactoryId, Box<dyn EventSectionFactory>>;

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use super::common_task_event;
    use crate::{
        benchmark::helpers::*,
        bindings::events_uapi::common_event,
        core::events::{FactoryId, COMMON_SECTION_CORE, COMMON_SECTION_TASK},
    };

    impl RawSectionBuilder for common_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self::default();
            build_raw_section(
                out,
                FactoryId::Common as u8,
                COMMON_SECTION_CORE as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }

    impl RawSectionBuilder for common_task_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let mut data = common_task_event::default();
            data.comm[0] = b'r' as i8;
            data.comm[1] = b'e' as i8;
            data.comm[2] = b't' as i8;
            data.comm[3] = b'i' as i8;
            data.comm[4] = b's' as i8;
            build_raw_section(
                out,
                FactoryId::Common as u8,
                COMMON_SECTION_TASK as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::event_section_factory;
    use crate::events::TestEvent;

    const DATA_TYPE_U64: u8 = 1;
    const DATA_TYPE_U128: u8 = 2;

    #[event_section_factory(FactoryId::Common)]
    #[derive(Default)]
    struct TestEventFactory {}

    impl RawEventSectionFactory for TestEventFactory {
        fn create(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
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
        factories.insert(FactoryId::Common, Box::<TestEventFactory>::default());

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
        let data = [4, 0, SectionId::Common as u8, DATA_TYPE_U64, 0, 0];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());

        // Valid event with a section too large. Section is ignored.
        let data = [4, 0, SectionId::Common as u8, DATA_TYPE_U64, 4, 0, 42, 42];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());
        let data = [6, 0, SectionId::Common as u8, DATA_TYPE_U64, 4, 0, 42, 42];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());

        // Valid event with a section having an invalid owner.
        let data = [4, 0, 0, DATA_TYPE_U64, 0, 0];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());
        let data = [4, 0, 255, DATA_TYPE_U64, 0, 0];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());

        // Valid event with an invalid data type.
        let data = [4, 0, SectionId::Common as u8, 0, 1, 0, 42];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());
        let data = [4, 0, SectionId::Common as u8, 255, 1, 0, 42];
        assert!(super::parse_raw_event(&data, &mut factories).is_ok());

        // Valid event but invalid section (too small).
        let data = [5, 0, SectionId::Common as u8, DATA_TYPE_U64, 1, 0, 42];
        assert!(super::parse_raw_event(&data, &mut factories).is_err());

        // Valid event, single section.
        let data = [
            12,
            0,
            SectionId::Common as u8,
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
        let section = event.get_section::<TestEvent>(SectionId::Common).unwrap();
        assert!(section.field0 == Some(42));

        // Valid event, multiple sections.
        let data = [
            44,
            0,
            // Section 1
            SectionId::Common as u8,
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
            SectionId::Common as u8,
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
            SectionId::Common as u8,
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
        let section = event.get_section::<TestEvent>(SectionId::Common).unwrap();
        assert!(section.field1 == Some(42));
        assert!(section.field2 == Some(1337));
    }
}
