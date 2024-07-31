//! # Common types
//!
//! Logic to retrieve common types from our probes whenever such type is seen
//! (initial use case is as function parameter, but this could be extended to
//! struct members). This is intended for small types (eg. enums) that are not
//! found all over the place and will always very likely provide useful
//! information. They have to fit in an u64 anyway.
//!
//! Currently supported types:
//! - None.

use anyhow::{bail, Result};

use crate::{
    core::events::{
        parse_single_raw_section, BpfRawSection, EventSectionFactory, FactoryId,
        RawEventSectionFactory,
    },
    event_section_factory,
    events::EventSection,
};

// Please keep in sync with its BPF counterpart.
#[repr(C)]
struct RawCommonTypeEvent {
    /// Type id of the common type retrieved.
    r#type: u32,
    /// The raw value we retrieved.
    val: u64,
}

#[event_section_factory(FactoryId::CommonType)]
#[derive(Default)]
pub(crate) struct CommonTypeEventFactory {}

impl RawEventSectionFactory for CommonTypeEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let raw = parse_single_raw_section::<RawCommonTypeEvent>(&raw_sections)?;

        match raw.r#type {
            x => bail!("Unexpected type id ({x})"),
        }
    }
}
