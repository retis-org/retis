//! Handles the BPF to Rust event retrieval and the unmarshaling process.

#![cfg_attr(test, allow(dead_code))]
#![cfg_attr(test, allow(unused_imports))]

use std::{collections::HashMap, mem, sync::mpsc, thread, time::Duration};

use anyhow::{anyhow, bail, Result};
use log::error;
use plain::Plain;

use super::Event;
use crate::{core::events::*, event_section, event_section_factory, module::ModuleId};

/// Timeout when polling for new events from BPF.
const BPF_EVENTS_POLL_TIMEOUT_MS: u64 = 200;

/// BPF events factory retrieving and unmarshaling events coming from the BPF
/// parts.
#[cfg(not(test))]
pub(crate) struct BpfEventsFactory {
    map: libbpf_rs::Map,
    /// Receiver channel to retrieve events from the processing loop.
    rxc: Option<mpsc::Receiver<Event>>,
}

#[cfg(not(test))]
impl BpfEventsFactory {
    pub(crate) fn new() -> Result<BpfEventsFactory> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        let map = libbpf_rs::Map::create(
            libbpf_rs::MapType::RingBuf,
            Some("events_map"),
            0,
            0,
            mem::size_of::<RawEvent>() as u32 * BPF_EVENTS_MAX,
            &opts,
        )
        .or_else(|e| bail!("Failed to create events map: {}", e))?;

        Ok(BpfEventsFactory { map, rxc: None })
    }

    /// Get the events map fd for reuse.
    pub(crate) fn map_fd(&self) -> i32 {
        self.map.fd()
    }
}

#[cfg(not(test))]
impl EventFactory for BpfEventsFactory {
    /// This starts the event polling mechanism. A dedicated thread is started
    /// for events to be retrieved and processed.
    fn start(
        &mut self,
        mut section_factories: HashMap<ModuleId, Box<dyn EventSectionFactory>>,
    ) -> Result<()> {
        if section_factories.is_empty() {
            bail!("No section factory, can't parse events, aborting");
        }

        // Create the sending and receiving channels.
        let (txc, rxc) = mpsc::channel();
        self.rxc = Some(rxc);

        // Closure to handle the raw events coming from the BPF part.
        let process_event = move |data: &[u8]| -> i32 {
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

        // Start an event polling thread.
        thread::spawn(move || loop {
            if let Err(e) = rb.poll(Duration::from_millis(BPF_EVENTS_POLL_TIMEOUT_MS)) {
                error!("Unexpected error while polling ({e})");
            }
        });

        Ok(())
    }

    /// Retrieve the next event. This is a blocking call and never returns EOF.
    fn next_event(&mut self, timeout: Option<Duration>) -> Result<Option<Event>> {
        let rxc = match &self.rxc {
            Some(rxc) => rxc,
            None => bail!("Can't get event, no rx channel found."),
        };

        Ok(match timeout {
            Some(timeout) => match rxc.recv_timeout(timeout) {
                Ok(event) => Some(event),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(e) => return Err(anyhow!(e)),
            },
            None => Some(rxc.recv()?),
        })
    }
}

fn parse_raw_event<'a>(
    data: &'a [u8],
    factories: &'a mut HashMap<ModuleId, Box<dyn EventSectionFactory>>,
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

#[event_section]
#[repr(C, packed)]
pub(crate) struct CommonEvent {
    /// Timestamp of when the event was generated.
    pub(crate) timestamp: u64,
}

unsafe impl Plain for CommonEvent {}

#[derive(Default)]
#[event_section_factory(CommonEvent)]
pub(crate) struct CommonEventFactory {}

impl RawEventSectionFactory for CommonEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        Ok(Box::new(parse_single_raw_section::<CommonEvent>(
            ModuleId::Common,
            raw_sections,
        )?))
    }
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
    fn start(&mut self, _: HashMap<ModuleId, Box<dyn EventSectionFactory>>) -> Result<()> {
        Ok(())
    }
    fn next_event(&mut self, _: Option<Duration>) -> Result<Option<Event>> {
        Ok(Some(Event::new()))
    }
}

/// Max number of events we can store at once in the shared map. Please keep in
/// sync with its BPF counterpart.
pub(super) const BPF_EVENTS_MAX: u32 = 512;

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
        let mut factories: HashMap<ModuleId, Box<dyn EventSectionFactory>> = HashMap::new();
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
