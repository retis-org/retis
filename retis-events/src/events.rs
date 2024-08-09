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

use std::{any::Any, collections::HashMap, fmt, str::FromStr};

use anyhow::{anyhow, bail, Result};
use log::debug;
use once_cell::sync::OnceCell;

use crate::{display::*, *};

/// Full event. Internal representation. The first key is the collector from
/// which the event sections originate. The second one is the field name of a
/// given (collector) event field.
#[derive(Default)]
pub struct Event(HashMap<SectionId, Box<dyn EventSection>>);

impl Event {
    pub fn new() -> Event {
        Event::default()
    }

    pub fn from_json(line: String) -> Result<Event> {
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
    pub fn insert_section(
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
    pub fn get_section<T: EventSection + 'static>(&self, owner: SectionId) -> Option<&T> {
        match self.0.get(&owner) {
            Some(section) => section.as_any().downcast_ref::<T>(),
            None => None,
        }
    }

    /// Get a reference to an event field by its owner and key.
    pub fn get_section_mut<T: EventSection + 'static>(
        &mut self,
        owner: SectionId,
    ) -> Option<&mut T> {
        match self.0.get_mut(&owner) {
            Some(section) => section.as_any_mut().downcast_mut::<T>(),
            None => None,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
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
        if let Some(common_type) = self.0.get(&SectionId::CommonType) {
            write!(f, " {}", common_type.display(format))?;
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
        (SectionId::Skb as u8..SectionId::_MAX as u8)
            .collect::<Vec<u8>>()
            .iter()
            .filter_map(|id| self.0.get(&SectionId::from_u8(*id).unwrap()))
            .try_for_each(|section| write!(f, "{sep}{}", section.display(format)))?;

        Ok(())
    }
}

/// List of unique event sections owners.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SectionId {
    Common = 1,
    Kernel = 2,
    Userspace = 3,
    Tracking = 4,
    SkbTracking = 5,
    SkbDrop = 6,
    CommonType = 7,
    Skb = 8,
    Ovs = 9,
    Nft = 10,
    Ct = 11,
    // TODO: use std::mem::variant_count once in stable.
    _MAX = 12,
}

impl FromStr for SectionId {
    type Err = anyhow::Error;

    /// Constructs an SectionId from a section unique str identifier.
    fn from_str(val: &str) -> Result<Self> {
        use SectionId::*;
        Ok(match val {
            "common" => Common,
            "kernel" => Kernel,
            "userspace" => Userspace,
            "tracking" => Tracking,
            "skb-tracking" => SkbTracking,
            "skb-drop" => SkbDrop,
            "skb" => Skb,
            "ovs" => Ovs,
            "nft" => Nft,
            "ct" => Ct,
            // CommonType does not have a corresponding Event.
            x => bail!("Can't construct a SectionId from {}", x),
        })
    }
}

impl SectionId {
    /// Constructs an SectionId from a section unique identifier
    pub fn from_u8(val: u8) -> Result<SectionId> {
        use SectionId::*;
        Ok(match val {
            1 => Common,
            2 => Kernel,
            3 => Userspace,
            4 => Tracking,
            5 => SkbTracking,
            6 => SkbDrop,
            7 => CommonType,
            8 => Skb,
            9 => Ovs,
            10 => Nft,
            11 => Ct,
            x => bail!("Can't construct a SectionId from {}", x),
        })
    }

    /// Converts an SectionId to a section unique str identifier.
    pub fn to_str(self) -> &'static str {
        use SectionId::*;
        match self {
            Common => "common",
            Kernel => "kernel",
            Userspace => "userspace",
            Tracking => "tracking",
            SkbTracking => "skb-tracking",
            SkbDrop => "skb-drop",
            Skb => "skb",
            Ovs => "ovs",
            Nft => "nft",
            Ct => "ct",
            // CommonType does not have a corresponding Event.
            CommonType => "_invalid",
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
    let insert_section = |events: &mut EventSectionMap, id, closure| -> Result<()> {
        events.insert(SectionId::from_u8(id)?.to_str().to_string(), closure);
        Ok(())
    };

    EVENT_SECTIONS.get_or_try_init(|| {
        let mut events = EventSectionMap::new();
        insert_section(&mut events, CommonEvent::SECTION_ID, |v| {
            Ok(Box::new(serde_json::from_value::<CommonEvent>(v)?))
        })?;
        insert_section(&mut events, KernelEvent::SECTION_ID, |v| {
            Ok(Box::new(serde_json::from_value::<KernelEvent>(v)?))
        })?;
        insert_section(&mut events, UserEvent::SECTION_ID, |v| {
            Ok(Box::new(serde_json::from_value::<UserEvent>(v)?))
        })?;
        insert_section(&mut events, SkbTrackingEvent::SECTION_ID, |v| {
            Ok(Box::new(serde_json::from_value::<SkbTrackingEvent>(v)?))
        })?;
        insert_section(&mut events, SkbDropEvent::SECTION_ID, |v| {
            Ok(Box::new(serde_json::from_value::<SkbDropEvent>(v)?))
        })?;
        insert_section(&mut events, SkbEvent::SECTION_ID, |v| {
            Ok(Box::new(serde_json::from_value::<SkbEvent>(v)?))
        })?;
        insert_section(&mut events, OvsEvent::SECTION_ID, |v| {
            Ok(Box::new(serde_json::from_value::<OvsEvent>(v)?))
        })?;
        insert_section(&mut events, NftEvent::SECTION_ID, |v| {
            Ok(Box::new(serde_json::from_value::<NftEvent>(v)?))
        })?;
        insert_section(&mut events, CtEvent::SECTION_ID, |v| {
            Ok(Box::new(serde_json::from_value::<CtEvent>(v)?))
        })?;

        // CommonType does not have a corresponding Event.
        Ok(events)
    })
}

/// The return value of EventFactory::next_event()
pub enum EventResult {
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
pub trait EventSection: EventSectionInternal + for<'a> EventDisplay<'a> {}
impl<T> EventSection for T where T: EventSectionInternal + for<'a> EventDisplay<'a> {}

/// EventSection helpers defined in the core for all events. Common definition
/// needs Sized but that is a requirement for all EventSection.
///
/// There should not be a need to have per-object implementations for this.
pub trait EventSectionInternal {
    fn section_id(&self) -> u8;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn to_json(&self) -> serde_json::Value;
}

// We need this as the value given as the input when deserializing something
// into an event could be mapped to (), e.g. serde_json::Value::Null.
impl EventSectionInternal for () {
    fn section_id(&self) -> u8 {
        SectionId::_MAX as u8
    }

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
