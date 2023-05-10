//! Internal representation of events. Those events can be marshaled/unmarshaled
//! to other formats to be stored or displayed. We currently support: JSON.
//!
//! As an example, a full JSON output should look like:
//!
//! {
//!     "version": "0.1.0",
//!     "hostname": "mymachine",
//!     "kernel": "6.0.8-300.fc37.x86_64",
//!     "events": [
//!         {
//!              "common": {
//!                  "symbol": "kfree_skb_reason",
//!                  "timestamp": "7322460997041"
//!              },
//!              "skb_tracking": {
//!                  "timestamp": "7322460997041",
//!                  "orig_head": "18446623346735780864",
//!                  "skb": "18446623349161350912",
//!                  "drop_reason": "0",
//!              },
//!              "skb": {
//!                  "etype": "34525"
//!              },
//!              "ovs": {
//!                  "ovs": "2.5.90",
//!                  "foo": "bar"
//!              }
//!         },
//!         ...
//!     ]
//! }

#![allow(dead_code)] // FIXME
#![allow(clippy::wrong_self_convention)]

use std::{any::Any, collections::HashMap, time::Duration};

use anyhow::{bail, Result};

use super::bpf::BpfRawSection;
use crate::module::ModuleId;

/// Full event. Internal representation. The first key is the collector from
/// which the event sections originate. The second one is the field name of a
/// given (collector) event field.
#[derive(Default)]
pub(crate) struct Event(HashMap<ModuleId, Box<dyn EventSection>>);

impl Event {
    pub(crate) fn new() -> Event {
        Event::default()
    }

    /// Insert a new event field into an event.
    pub(crate) fn insert_section(
        &mut self,
        owner: ModuleId,
        section: Box<dyn EventSection>,
    ) -> Result<()> {
        if self.0.get(&owner).is_some() {
            bail!("Section for {} already found in the event", owner);
        }

        self.0.insert(owner, section);
        Ok(())
    }

    /// Get a reference to an event field by its owner and key.
    pub(crate) fn get_section<T: EventSection + 'static>(&self, owner: ModuleId) -> Option<&T> {
        match self.0.get(&owner) {
            Some(section) => section.as_any().downcast_ref::<T>(),
            None => None,
        }
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        let mut event = serde_json::Map::new();

        for (owner, section) in self.0.iter() {
            event.insert(owner.to_str().to_string(), section.to_json());
        }

        serde_json::Value::Object(event)
    }
}

pub(crate) type SectionFactories = HashMap<ModuleId, Box<dyn EventSectionFactory>>;

/// Implemented by objects generating events from a given source (BPF, file,
/// etc).
pub(crate) trait EventFactory {
    /// Starts the factory events collection.
    fn start(
        &mut self,
        section_factories: HashMap<ModuleId, Box<dyn EventSectionFactory>>,
    ) -> Result<()>;
    /// Stops the factory events collection.
    fn stop(&mut self) -> Result<()>;
    /// Gets the next Event.
    ///
    /// Either returns EOF if the underlying source is consumed, or is a
    /// blocking call and waits for more data. Optionally a timeout can be
    /// given, in such case None can be returned. Specific factories should
    /// document those behaviors.
    fn next_event(&mut self, timeout: Option<Duration>) -> Result<Option<Event>>;
}

/// Per-module event section, should map 1:1 with a ModuleId. Requiring specific
/// traits to be implemented helps handling those sections in the core directly
/// without requiring all modules to serialize and deserialize their events by
/// hand (except for the special case of BPF section events as there is an n:1
/// mapping there).
///
/// Please use `#[retis_derive::event_section]` to implement the common traits.
///
/// The underlying objects are free to hold their data in any way, although
/// having a proper structure is encouraged as it allows easier consumption at
/// post-processing. Those objects can also define their own specialized
/// helpers.
pub(crate) trait EventSection: EventSectionInternal {}
impl<T> EventSection for T where T: EventSectionInternal {}

/// EventSection helpers defined in the core for all events. Common definition
/// needs Sized but that is a requirement for all EventSection.
///
/// There should not be a need to have per-object implementations for this.
pub(crate) trait EventSectionInternal {
    fn as_any(&self) -> &dyn Any;
    fn to_json(&self) -> serde_json::Value;
}

// We need this as the value given as the input when deserializing something
// into an event could be mapped to (), e.g. serde_json::Value::Null.
impl EventSectionInternal for () {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
}

/// EventSection factory, providing helpers to create event sections from
/// various formats.
///
/// Please use `#[retis_derive::event_section_factory(SectionType)]` to
/// implement the common traits.
pub(crate) trait EventSectionFactory:
    RawEventSectionFactory + SerdeEventSectionFactory
{
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Event section factory helpers to convert from BPF raw events. Requires a
/// per-object implementation.
pub(crate) trait RawEventSectionFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>>;
}

/// Event section factory helpers to convert from serde compatible inputs.
///
/// In most cases an event section object should not have to define thoses as
/// there is an implementation for serde::Deserialize + serde::Serialize.
pub(crate) trait SerdeEventSectionFactory {
    fn from_json(&self, val: serde_json::Value) -> Result<Box<dyn EventSection>>;
}
