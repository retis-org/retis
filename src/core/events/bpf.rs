//! Handles the BPF to Rust event retrieval and the unmarshaling process.

#![cfg_attr(test, allow(dead_code))]
#![cfg_attr(test, allow(unused_imports))]

use std::{
    any::Any,
    collections::HashMap,
    fmt, mem,
    sync::{mpsc, Arc},
    thread,
    time::Duration,
};

use anyhow::{bail, Result};
use log::error;
use plain::Plain;

use super::{Event, EventField};
use crate::{core::workaround::SendableRingBuffer, event_field};

/// Timeout when polling for new events from BPF.
const BPF_EVENTS_POLL_TIMEOUT_MS: u64 = 200;

/// Unmarshaling Cache. It's a HashMap that can be used by any Unmarshaler to store and retrieve
/// arbitrary data that can speed up event processing.
/// Unmarshalers can't expect any value to be there as unmarshaler presence or calls ordering
/// is not guaranteed.
type Cache = HashMap<String, Box<dyn Any>>;

/// Type of the unmarshaler closures. Takes a raw section as an input and
/// returns an unmarshaled event section. The closure is chosen based on the
/// unique owner id of the raw event.
pub(crate) type EventUnmarshaler =
    dyn Fn(&BpfRawSection, &mut Vec<EventField>, &mut Cache) -> Result<()>;

// Define a private type for unmarshalers as we'll use it more than once.
type Unmarshalers = HashMap<BpfEventOwner, Box<EventUnmarshaler>>;

/// API to retrieve and unmarshal events coming from the BPF parts.
#[cfg(not(test))]
pub(crate) struct BpfEvents {
    map: libbpf_rs::Map,
    /// HashMap of unmarshalers.
    unmarshalers: Arc<Unmarshalers>,
    /// Receiver channel to retrieve events from the processing loop.
    rxc: Option<mpsc::Receiver<Event>>,
}

#[cfg(not(test))]
impl BpfEvents {
    pub(crate) fn new() -> Result<BpfEvents> {
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

        let mut events = BpfEvents {
            map,
            unmarshalers: Arc::new(HashMap::new()),
            rxc: None,
        };

        events.register_unmarshaler(
            BpfEventOwner::Common,
            Box::new(|raw_section, fields, _| {
                if raw_section.header.data_type != 1 {
                    bail!("Unknown data type");
                }

                if raw_section.data.len() != 8 {
                    bail!(
                        "Section data is not the expected size {} != 8",
                        raw_section.data.len()
                    );
                }

                let timestamp = u64::from_ne_bytes(raw_section.data[0..8].try_into()?);
                fields.push(event_field!("timestamp", timestamp));
                Ok(())
            }),
        )?;

        Ok(events)
    }

    /// Register a new unmarshaler closure to convert raw sections into event
    /// sections.
    pub(crate) fn register_unmarshaler(
        &mut self,
        owner: BpfEventOwner,
        unmarshaler: Box<EventUnmarshaler>,
    ) -> Result<()> {
        if self.unmarshalers.contains_key(&owner) {
            bail!("Unmarshaler already registered for owner {}", owner);
        }

        (*Arc::get_mut(&mut self.unmarshalers).unwrap()).insert(owner, unmarshaler);
        Ok(())
    }

    /// This starts the event polling mechanism. A dedicated thread is started
    /// and events are retrieved and processed there. This is a non-blocking
    /// call.
    pub(crate) fn start_polling(&mut self) -> Result<()> {
        // self.unmarshalers is an Arc<> so we're still pointing to the common
        // unmarshalers map.
        let unmarshalers = self.unmarshalers.clone();

        // Create the sending and receiving channels.
        let (txc, rxc) = mpsc::channel();
        self.rxc = Some(rxc);

        // Initialize unmarshaling cache.
        let mut cache = Cache::new();

        // Closure to handle the raw events coming from the BPF part. We're
        // moving our Arc clone pointing to unmarshalers there and the tx
        // channel.
        let process_event = move |data: &[u8]| -> i32 {
            // Parse the raw event.
            let event = match parse_raw_event(data, &unmarshalers, &mut cache) {
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
        let rb = SendableRingBuffer::from(rb.build()?);

        // Start an event polling thread.
        thread::spawn(move || {
            let rb = rb.get();
            loop {
                rb.poll(Duration::from_millis(BPF_EVENTS_POLL_TIMEOUT_MS))
                    .unwrap();
            }
        });

        Ok(())
    }

    /// Retrieve the next event. This is a blocking call.
    pub(crate) fn poll(&self) -> Result<Event> {
        match &self.rxc {
            Some(rxc) => Ok(rxc.recv()?),
            None => bail!("Can't get event, no rx channel found."),
        }
    }

    /// Get the events map fd for reuse.
    pub(crate) fn map_fd(&self) -> i32 {
        self.map.fd()
    }
}

fn parse_raw_event(data: &[u8], unmarshalers: &Unmarshalers, cache: &mut Cache) -> Result<Event> {
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

    // Let's loop through the raw event sections. Cursor is initialized
    // to sizeof(u16) as we already read the raw event size above.
    let mut cursor = 2;
    let mut event = Event::new();
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
        let owner = match BpfEventOwner::from_u8(raw_section.header.owner) {
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

        // Try getting the right unmarshaler.
        let unmarshaler = match unmarshalers.get(&owner) {
            Some(unmarshaler) => unmarshaler,
            None => {
                error!("Could not get unmarshaler for owner {}", owner);
                continue;
            }
        };

        // Unmarshall the section.
        let mut fields = Vec::new();
        if let Err(e) = unmarshaler(&raw_section, &mut fields, cache) {
            let size = raw_section.header.size; // unaligned
            error!(
                "Could not unmarshal section (owner: {} data_type: {} size: {}): {}",
                owner, raw_section.header.data_type, size, e
            );
            continue;
        }

        // Fill the event with unmarshaled sections. Unwrap as we know
        // it's a valid owner.
        for field in fields {
            event.insert(owner.to_str_ref().unwrap(), field);
        }
    }

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

// We use a dummy implementation of BpfEvents to allow unit tests to pass.
// This is fine as no function in the above can really be tested.
#[cfg(test)]
pub(crate) struct BpfEvents;

#[cfg(test)]
impl BpfEvents {
    pub(crate) fn new() -> Result<BpfEvents> {
        Ok(BpfEvents {})
    }
    pub(crate) fn register_unmarshaler(
        &mut self,
        _: BpfEventOwner,
        _: Box<EventUnmarshaler>,
    ) -> Result<()> {
        Ok(())
    }
    pub(crate) fn start_polling(&self) -> Result<()> {
        Ok(())
    }
    pub(crate) fn poll(&self) -> Result<Event> {
        Ok(Event::new())
    }
    pub(crate) fn map_fd(&self) -> i32 {
        0
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
#[derive(Default)]
pub(crate) struct BpfRawSection {
    pub(crate) header: BpfRawSectionHeader,
    pub(crate) data: Vec<u8>,
}

/// Raw event section header shared between the Rust and BPF part. Please keep
/// in sync with its BPF counterpart.
#[repr(C, packed)]
#[derive(Default)]
pub(crate) struct BpfRawSectionHeader {
    pub(super) owner: u8,
    pub(crate) data_type: u8,
    pub(crate) size: u16,
}

unsafe impl Plain for BpfRawSectionHeader {}

/// List of unique owner ids. Please keep in sync with its BPF counterpart. An
/// owner is a module responsible of given sections types. The section "unique
/// id" is (owner id, data type id).
#[derive(Debug, Eq, Hash, PartialEq)]
pub(crate) enum BpfEventOwner {
    Common = 1,
    Kernel = 2,
    Userspace = 3,
    CollectorSkbTracking = 4,
    CollectorSkb = 5,
    CollectorOvs = 6,
}

impl BpfEventOwner {
    pub(super) fn from_u8(val: u8) -> Result<BpfEventOwner> {
        use BpfEventOwner::*;
        let owner = match val {
            1 => Common,
            2 => Kernel,
            3 => Userspace,
            4 => CollectorSkbTracking,
            5 => CollectorSkb,
            6 => CollectorOvs,
            x => bail!("Can't construct a BpfEventOwner from {}", x),
        };
        Ok(owner)
    }

    pub(super) fn to_str_ref(&self) -> Result<&str> {
        use BpfEventOwner::*;
        let ret = match self {
            Common => "common",
            Kernel => "kernel",
            Userspace => "userspace",
            CollectorSkbTracking => "skb-tracking",
            CollectorSkb => "skb",
            CollectorOvs => "ovs",
        };
        Ok(ret)
    }
}

// Allow using BpfEventOwner in log messages.
impl fmt::Display for BpfEventOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA_TYPE_U64: u8 = 1;
    const DATA_TYPE_U128: u8 = 2;

    #[test]
    fn parse_raw_event() {
        let mut unmarshalers = Unmarshalers::new();
        let mut cache = Cache::new();

        // Let's use the Common probe type for our tests.
        unmarshalers.insert(
            BpfEventOwner::Common,
            Box::new(|raw_section, fields, _| {
                let len = raw_section.data.len();

                match raw_section.header.data_type {
                    DATA_TYPE_U64 => {
                        if len != 8 {
                            bail!("Invalid section for data type 1");
                        }

                        fields.push(event_field!(
                            "field0",
                            u64::from_ne_bytes(raw_section.data[0..8].try_into()?)
                        ));
                    }
                    DATA_TYPE_U128 => {
                        if len != 16 {
                            bail!("Invalid section for data type 2");
                        }

                        fields.push(event_field!(
                            "field1",
                            u64::from_ne_bytes(raw_section.data[0..8].try_into()?)
                        ));
                        fields.push(event_field!(
                            "field2",
                            u64::from_ne_bytes(raw_section.data[8..16].try_into()?)
                        ));
                    }
                    _ => bail!("Invalid data type"),
                }
                Ok(())
            }),
        );

        // Empty event.
        let data = [];
        assert!(super::parse_raw_event(&data, &unmarshalers, &mut cache).is_err());

        // Uncomplete event size.
        let data = [0];
        assert!(super::parse_raw_event(&data, &unmarshalers, &mut cache).is_err());

        // Valid event size but empty event.
        let data = [0, 0];
        assert!(super::parse_raw_event(&data, &unmarshalers, &mut cache).is_err());

        // Valid event size but incomplete event.
        let data = [42, 0];
        assert!(super::parse_raw_event(&data, &unmarshalers, &mut cache).is_err());
        let data = [2, 0, 42];
        assert!(super::parse_raw_event(&data, &unmarshalers, &mut cache).is_err());

        // Valid event with a single empty section. Section is ignored.
        let data = [4, 0, BpfEventOwner::Common as u8, DATA_TYPE_U64, 0, 0];
        assert!(super::parse_raw_event(&data, &unmarshalers, &mut cache).is_ok());

        // Valid event with a section too large. Section is ignored.
        let data = [
            4,
            0,
            BpfEventOwner::Common as u8,
            DATA_TYPE_U64,
            4,
            0,
            42,
            42,
        ];
        assert!(super::parse_raw_event(&data, &unmarshalers, &mut cache).is_ok());
        let data = [
            6,
            0,
            BpfEventOwner::Common as u8,
            DATA_TYPE_U64,
            4,
            0,
            42,
            42,
        ];
        assert!(super::parse_raw_event(&data, &unmarshalers, &mut cache).is_ok());

        // Valid event with a section having an invalid owner.
        let data = [4, 0, 0, DATA_TYPE_U64, 0, 0];
        assert!(super::parse_raw_event(&data, &unmarshalers, &mut cache).is_ok());
        let data = [4, 0, 255, DATA_TYPE_U64, 0, 0];
        assert!(super::parse_raw_event(&data, &unmarshalers, &mut cache).is_ok());

        // Valid event with an invalid data type.
        let data = [4, 0, BpfEventOwner::Common as u8, 0, 1, 0, 42];
        assert!(super::parse_raw_event(&data, &unmarshalers, &mut cache).is_ok());
        let data = [4, 0, BpfEventOwner::Common as u8, 255, 1, 0, 42];
        assert!(super::parse_raw_event(&data, &unmarshalers, &mut cache).is_ok());

        // Valid event but invalid section (too small).
        let data = [5, 0, BpfEventOwner::Common as u8, DATA_TYPE_U64, 1, 0, 42];
        let res = super::parse_raw_event(&data, &unmarshalers, &mut cache);
        assert!(res.unwrap().len() == 0);

        // Valid event, single section.
        let data = [
            12,
            0,
            BpfEventOwner::Common as u8,
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
        let event = super::parse_raw_event(&data, &unmarshalers, &mut cache).unwrap();
        let field = event.get::<u64>("common", "field0").unwrap();
        assert!(field == Some(&42));

        // Valid event, multiple sections.
        let data = [
            44,
            0,
            // Section 1
            BpfEventOwner::Common as u8,
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
            BpfEventOwner::Common as u8,
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
            BpfEventOwner::Common as u8,
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
        let event = super::parse_raw_event(&data, &unmarshalers, &mut cache).unwrap();
        let field = event.get::<u64>("common", "field1").unwrap();
        assert!(field == Some(&42));
        let field = event.get::<u64>("common", "field2").unwrap();
        assert!(field == Some(&1337));

        // Test an unknown field and type mismatch on the above event.
        let field = event.get::<u64>("common", "invalid").unwrap();
        assert!(field.is_none());
        assert!(event.get::<i64>("common", "field1").is_err());
    }
}
