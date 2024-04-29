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

use std::{any::Any, collections::HashMap, fmt};

use anyhow::{anyhow, bail, Result};
use log::debug;
use once_cell::sync::OnceCell;

use super::*;

/// Full event. Internal representation. The first key is the collector from
/// which the event sections originate. The second one is the field name of a
/// given (collector) event field.
#[derive(Default)]
pub(crate) struct Event(HashMap<SectionId, Box<dyn EventSection>>);

impl Event {
    pub(crate) fn new() -> Event {
        Event::default()
    }

    pub(crate) fn from_json(line: String) -> Result<Event> {
        let mut event = Event::new();

        let mut event_js: HashMap<String, serde_json::Value> = serde_json::from_str(line.as_str())
            .map_err(|e| anyhow!("Failed to parse json event at line {line}: {e}"))?;

        for (owner, value) in event_js.drain() {
            let owner_mod = SectionId::from_str(&owner)?;
            let parser = event_sections()?
                .get(&owner)
                .ok_or_else(|| anyhow!("json contains an unsupported event {}", owner))?;

            debug!("Unmarshaling event section {owner}: {value}");
            event.insert_section(
                owner_mod,
                parser(value).map_err(|e| {
                    anyhow!("Failed to create EventSection for owner {owner} from json: {e}")
                })?,
            )?;
        }
        Ok(event)
    }

    /// Insert a new event field into an event.
    pub(crate) fn insert_section(
        &mut self,
        owner: SectionId,
        section: Box<dyn EventSection>,
    ) -> Result<()> {
        if self.0.contains_key(&owner) {
            bail!("Section for {} already found in the event", owner);
        }

        self.0.insert(owner, section);
        Ok(())
    }

    /// Get a reference to an event field by its owner and key.
    pub(crate) fn get_section<T: EventSection + 'static>(&self, owner: SectionId) -> Option<&T> {
        match self.0.get(&owner) {
            Some(section) => section.as_any().downcast_ref::<T>(),
            None => None,
        }
    }

    /// Get a reference to an event field by its owner and key.
    pub(crate) fn get_section_mut<T: EventSection + 'static>(
        &mut self,
        owner: SectionId,
    ) -> Option<&mut T> {
        match self.0.get_mut(&owner) {
            Some(section) => section.as_any_mut().downcast_mut::<T>(),
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

impl EventFmt for Event {
    fn event_fmt(&self, f: &mut std::fmt::Formatter, format: DisplayFormat) -> std::fmt::Result {
        // First format the first event line starting with the always-there
        // {common} section, followed by the {kernel} or {user} one.
        write!(
            f,
            "{}",
            self.0.get(&SectionId::Common).unwrap().display(format)
        )?;
        if let Some(kernel) = self.0.get(&SectionId::Kernel) {
            write!(f, " {}", kernel.display(format))?;
        } else if let Some(user) = self.0.get(&SectionId::Userspace) {
            write!(f, " {}", user.display(format))?;
        }

        // If we do have tracking and/or drop sections, put them there too.
        // Special case the global tracking information from here for now.
        if let Some(tracking) = self.0.get(&SectionId::Tracking) {
            write!(f, " {}", tracking.display(format))?;
        } else if let Some(skb_tracking) = self.0.get(&SectionId::SkbTracking) {
            write!(f, " {}", skb_tracking.display(format))?;
        }
        if let Some(skb_drop) = self.0.get(&SectionId::SkbDrop) {
            write!(f, " {}", skb_drop.display(format))?;
        }

        // If we have a stack trace, show it.
        if let Some(kernel) = self.get_section::<KernelEvent>(SectionId::Kernel) {
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
        (SectionId::Skb.to_u8()..SectionId::_MAX.to_u8())
            .collect::<Vec<u8>>()
            .iter()
            .filter_map(|id| self.0.get(&SectionId::from_u8(*id).unwrap()))
            .try_for_each(|section| write!(f, "{sep}{}", section.display(format)))?;

        Ok(())
    }
}

/// List of unique event sections owners.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum SectionId {
    Common = 1,
    Kernel = 2,
    Userspace = 3,
    Tracking = 4,
    SkbTracking = 5,
    SkbDrop = 6,
    Skb = 7,
    Ovs = 8,
    Nft = 9,
    Ct = 10,
    // TODO: use std::mem::variant_count once in stable.
    _MAX = 11,
}

impl SectionId {
    /// Constructs an SectionId from a section unique identifier. Please
    /// keep in sync with its BPF counterpart.
    pub(crate) fn from_u8(val: u8) -> Result<SectionId> {
        use SectionId::*;
        Ok(match val {
            1 => Common,
            2 => Kernel,
            3 => Userspace,
            4 => Tracking,
            5 => SkbTracking,
            6 => SkbDrop,
            7 => Skb,
            8 => Ovs,
            9 => Nft,
            10 => Ct,
            x => bail!("Can't construct a SectionId from {}", x),
        })
    }

    /// Converts an SectionId to a section unique identifier. Please
    /// keep in sync with its BPF counterpart.
    #[allow(dead_code)]
    pub(crate) fn to_u8(self) -> u8 {
        use SectionId::*;
        match self {
            Common => 1,
            Kernel => 2,
            Userspace => 3,
            Tracking => 4,
            SkbTracking => 5,
            SkbDrop => 6,
            Skb => 7,
            Ovs => 8,
            Nft => 9,
            Ct => 10,
            _MAX => 11,
        }
    }

    /// Constructs an SectionId from a section unique str identifier.
    pub(crate) fn from_str(val: &str) -> Result<SectionId> {
        use SectionId::*;
        Ok(match val {
            CommonEvent::SECTION_NAME => Common,
            KernelEvent::SECTION_NAME => Kernel,
            UserEvent::SECTION_NAME => Userspace,
            TrackingInfo::SECTION_NAME => Tracking,
            SkbTrackingEvent::SECTION_NAME => SkbTracking,
            SkbDropEvent::SECTION_NAME => SkbDrop,
            SkbEvent::SECTION_NAME => Skb,
            OvsEvent::SECTION_NAME => Ovs,
            NftEvent::SECTION_NAME => Nft,
            CtEvent::SECTION_NAME => Ct,
            x => bail!("Can't construct a SectionId from {}", x),
        })
    }

    /// Converts an SectionId to a section unique str identifier.
    pub(crate) fn to_str(self) -> &'static str {
        use SectionId::*;
        match self {
            Common => CommonEvent::SECTION_NAME,
            Kernel => KernelEvent::SECTION_NAME,
            Userspace => UserEvent::SECTION_NAME,
            Tracking => TrackingInfo::SECTION_NAME,
            SkbTracking => SkbTrackingEvent::SECTION_NAME,
            SkbDrop => SkbDropEvent::SECTION_NAME,
            Skb => SkbEvent::SECTION_NAME,
            Ovs => OvsEvent::SECTION_NAME,
            Nft => NftEvent::SECTION_NAME,
            Ct => CtEvent::SECTION_NAME,
            _MAX => "_max",
        }
    }
}

// Allow using SectionId in log messages.
impl fmt::Display for SectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

type EventSectionMap = HashMap<String, fn(serde_json::Value) -> Result<Box<dyn EventSection>>>;
static EVENT_SECTIONS: OnceCell<EventSectionMap> = OnceCell::new();

fn event_sections() -> Result<&'static EventSectionMap> {
    EVENT_SECTIONS.get_or_try_init(|| {
        let mut events = EventSectionMap::new();
        events.insert(CommonEvent::SECTION_NAME.to_string(), |v| {
            Ok(Box::new(serde_json::from_value::<CommonEvent>(v)?))
        });
        events.insert(KernelEvent::SECTION_NAME.to_string(), |v| {
            Ok(Box::new(serde_json::from_value::<KernelEvent>(v)?))
        });
        events.insert(UserEvent::SECTION_NAME.to_string(), |v| {
            Ok(Box::new(serde_json::from_value::<UserEvent>(v)?))
        });
        events.insert(SkbTrackingEvent::SECTION_NAME.to_string(), |v| {
            Ok(Box::new(serde_json::from_value::<SkbTrackingEvent>(v)?))
        });
        events.insert(SkbDropEvent::SECTION_NAME.to_string(), |v| {
            Ok(Box::new(serde_json::from_value::<SkbDropEvent>(v)?))
        });
        events.insert(SkbEvent::SECTION_NAME.to_string(), |v| {
            Ok(Box::new(serde_json::from_value::<SkbEvent>(v)?))
        });
        events.insert(OvsEvent::SECTION_NAME.to_string(), |v| {
            Ok(Box::new(serde_json::from_value::<OvsEvent>(v)?))
        });
        events.insert(NftEvent::SECTION_NAME.to_string(), |v| {
            Ok(Box::new(serde_json::from_value::<NftEvent>(v)?))
        });
        events.insert(CtEvent::SECTION_NAME.to_string(), |v| {
            Ok(Box::new(serde_json::from_value::<CtEvent>(v)?))
        });
        Ok(events)
    })
}

/// The return value of EventFactory::next_event()
pub(crate) enum EventResult {
    /// The Factory was able to create a new event.
    Event(Event),
    /// The source has been consumed.
    Eof,
    /// The timeout went off but a new attempt to retrieve an event might succeed.
    Timeout,
}

/// Per-module event section, should map 1:1 with a SectionId. Requiring specific
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
}
