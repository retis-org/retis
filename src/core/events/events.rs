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

use super::{bpf::BpfRawSection, DisplayFormat, EventDisplay, EventFmt};
use crate::{core::probe::kernel::KernelEvent, module::ModuleId};

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

    /// Get a reference to an event field by its owner and key.
    pub(crate) fn get_section_mut<T: EventSection + 'static>(
        &mut self,
        owner: ModuleId,
    ) -> Option<&mut T> {
        match self.0.get_mut(&owner) {
            Some(section) => section.as_any_mut().downcast_mut::<T>(),
            None => None,
        }
    }

    #[allow(clippy::borrowed_box)]
    pub(super) fn get(&self, owner: ModuleId) -> Option<&Box<dyn EventSection>> {
        self.0.get(&owner)
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        let mut event = serde_json::Map::new();

        for (owner, section) in self.0.iter() {
            event.insert(owner.to_str().to_string(), section.to_json());
        }

        serde_json::Value::Object(event)
    }
}

impl EventFmt for Event {
    fn event_fmt(&self, f: &mut std::fmt::Formatter, format: DisplayFormat) -> std::fmt::Result {
        // First format the first event line starting with the always-there
        // {common} section, followed by the {kernel} or {user} one.
        write!(
            f,
            "{}",
            self.0.get(&ModuleId::Common).unwrap().display(format)
        )?;
        if let Some(kernel) = self.0.get(&ModuleId::Kernel) {
            write!(f, " {}", kernel.display(format))?;
        } else if let Some(user) = self.0.get(&ModuleId::Userspace) {
            write!(f, " {}", user.display(format))?;
        }

        // If we do have tracking and/or drop sections, put them there too.
        // Special case the global tracking information from here for now.
        if let Some(tracking) = self.0.get(&ModuleId::Tracking) {
            write!(f, " {}", tracking.display(format))?;
        } else if let Some(skb_tracking) = self.0.get(&ModuleId::SkbTracking) {
            write!(f, " {}", skb_tracking.display(format))?;
        }
        if let Some(skb_drop) = self.0.get(&ModuleId::SkbDrop) {
            write!(f, " {}", skb_drop.display(format))?;
        }

        // If we have a stack trace, show it.
        if let Some(kernel) = self.get_section::<KernelEvent>(ModuleId::Kernel) {
            if let Some(stack) = &kernel.stack_trace {
                match format {
                    DisplayFormat::SingleLine => write!(f, " {}", stack.display(format))?,
                    DisplayFormat::MultiLine => write!(f, "\n{}", stack.display(format))?,
                }
            }
        }

        let sep = match format {
            DisplayFormat::SingleLine => " ",
            DisplayFormat::MultiLine => "\n  ",
        };

        // Finally show all sections.
        (ModuleId::Skb.to_u8()..ModuleId::_MAX.to_u8())
            .collect::<Vec<u8>>()
            .iter()
            .filter_map(|id| self.0.get(&ModuleId::from_u8(*id).unwrap()))
            .try_for_each(|section| write!(f, "{sep}{}", section.display(format)))?;

        Ok(())
    }
}

/// Type alias to refer to the commonly used EventSectionFactory HashMap.
pub(crate) type SectionFactories = HashMap<ModuleId, Box<dyn EventSectionFactory>>;

/// The return value of EventFactory::next_event()
pub(crate) enum EventResult {
    /// The Factory was able to create a new event.
    Event(Event),
    /// The source has been consumed.
    Eof,
    /// The timeout went off but a new attempt to retrieve an event might succeed.
    Timeout,
}

/// Implemented by objects generating events from a given source (BPF, file,
/// etc).
pub(crate) trait EventFactory {
    /// Starts the factory events collection.
    fn start(&mut self, section_factories: SectionFactories) -> Result<()>;
    /// Stops the factory events collection.
    fn stop(&mut self) -> Result<()>;
    /// Gets the next Event.
    ///
    /// Either returns EOF if the underlying source is consumed, or is a
    /// blocking call and waits for more data. Optionally a timeout can be
    /// given, in such case None can be returned. Specific factories should
    /// document those behaviors.
    fn next_event(&mut self, timeout: Option<Duration>) -> Result<EventResult>;
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
pub(crate) trait EventSection: EventSectionInternal + for<'a> EventDisplay<'a> {}
impl<T> EventSection for T where T: EventSectionInternal + for<'a> EventDisplay<'a> {}

/// EventSection helpers defined in the core for all events. Common definition
/// needs Sized but that is a requirement for all EventSection.
///
/// There should not be a need to have per-object implementations for this.
pub(crate) trait EventSectionInternal {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn to_json(&self) -> serde_json::Value;
    fn to_py(&self, py: pyo3::Python<'_>) -> pyo3::PyObject;
}

// We need this as the value given as the input when deserializing something
// into an event could be mapped to (), e.g. serde_json::Value::Null.
impl EventSectionInternal for () {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    fn to_py(&self, py: pyo3::Python<'_>) -> pyo3::PyObject {
        py.None().into()
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
