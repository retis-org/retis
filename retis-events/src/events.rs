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

#![allow(clippy::wrong_self_convention)]

use std::any::Any;

use anyhow::{anyhow, Result};

use crate::{display::*, *};

/// Full event. Internal representation
#[serde_with::skip_serializing_none]
#[derive(Default, Debug, Clone, serde::Deserialize, serde::Serialize)]
// For backwards compatiblity reasons, we keep section names in kebab-case.
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all))]
pub struct Event {
    /// Common section.
    pub common: Option<CommonEvent>,
    /// Kernel section.
    pub kernel: Option<KernelEvent>,
    /// Userpace section.
    pub userspace: Option<UserEvent>,
    /// Tracking section.
    pub tracking: Option<TrackingInfo>,
    /// Skb tracking section.
    pub skb_tracking: Option<SkbTrackingEvent>,
    /// Skb drop section.
    pub skb_drop: Option<SkbDropEvent>,
    /// Skb section.
    pub skb: Option<SkbEvent>,
    /// OVS section.
    pub ovs: Option<OvsEvent>,
    /// OVS-detrace section.
    pub ovs_detrace: Option<OvsFlowInfoEvent>,
    /// Nft section
    pub nft: Option<NftEvent>,
    /// Ct section
    pub ct: Option<CtEvent>,
    /// Startup event
    pub startup: Option<StartupEvent>,

    #[cfg(feature = "test-events")]
    pub test: Option<TestEvent>,
}

impl Event {
    pub fn new() -> Event {
        Event::default()
    }

    /// Create an Event from a json string.
    pub(crate) fn from_json(line: String) -> Result<Event> {
        Ok(serde_json::from_str(line.as_str())?)
    }

    pub fn to_json(&self) -> Result<serde_json::Value> {
        Ok(serde_json::to_value(self)?)
    }
}

impl EventFmt for Event {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> std::fmt::Result {
        // First format the first event line starting with the always-there
        // {common} section, followed by the {kernel} or {user} one.
        self.common.as_ref().unwrap().event_fmt(f, format)?;
        if let Some(kernel) = &self.kernel {
            write!(f, " ")?;
            kernel.event_fmt(f, format)?;
        } else if let Some(user) = &self.userspace {
            write!(f, " ")?;
            user.event_fmt(f, format)?;
        }

        // If we do have tracking and/or drop sections, put them there too.
        // Special case the global tracking information from here for now.
        if let Some(tracking) = &self.tracking {
            write!(f, " ")?;
            tracking.event_fmt(f, format)?;
        } else if let Some(skb_tracking) = &self.skb_tracking {
            write!(f, " ")?;
            skb_tracking.event_fmt(f, format)?;
        }
        if let Some(skb_drop) = &self.skb_drop {
            write!(f, " ")?;
            skb_drop.event_fmt(f, format)?;
        }

        // Separator between each following sections.
        let sep = if format.multiline { '\n' } else { ' ' };

        // If we have a stack trace, show it.
        if let Some(kernel) = &self.kernel {
            if let Some(stack) = &kernel.stack_trace {
                f.conf.inc_level(4);
                write!(f, "{sep}")?;
                stack.event_fmt(f, format)?;
                f.conf.reset_level();
            }
        }

        f.conf.inc_level(2);

        /* Format the rest of the optional fields. */
        [
            self.skb.as_ref().map(|f| f as &dyn EventDisplay),
            self.ovs.as_ref().map(|f| f as &dyn EventDisplay),
            self.ovs_detrace.as_ref().map(|f| f as &dyn EventDisplay),
            self.nft.as_ref().map(|f| f as &dyn EventDisplay),
            self.ct.as_ref().map(|f| f as &dyn EventDisplay),
            self.startup.as_ref().map(|f| f as &dyn EventDisplay),
        ]
        .iter()
        .try_for_each(|field| {
            if let Some(field) = field {
                write!(f, "{sep}")?;
                return field.event_fmt(f, format);
            }
            Ok(())
        })?;

        f.conf.reset_level();
        Ok(())
    }
}

/// Event section, should map 1:1 with a SectionId. Requiring specific traits to
/// be implemented helps handling those sections in the core directly without
/// requiring all section to serialize and deserialize their part by hand
/// (except for the special case of BPF section events as there is an n:1
/// mapping there).
///
/// Please use `#[retis_derive::event_section]` to implement the common traits.
///
/// The underlying objects are free to hold their data in any way, although
/// having a proper structure is encouraged as it allows easier consumption at
/// post-processing. Those objects can also define their own specialized
/// helpers.
pub trait EventSection: EventSectionInternal + for<'a> EventDisplay<'a> + Send {}
impl<T> EventSection for T where T: EventSectionInternal + for<'a> EventDisplay<'a> + Send {}

/// EventSection helpers defined in the core for all events. Common definition
/// needs Sized but that is a requirement for all EventSection.
///
/// There should not be a need to have per-object implementations for this.
pub trait EventSectionInternal {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn to_json(&self) -> serde_json::Value;
    #[cfg(feature = "python")]
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

    #[cfg(feature = "python")]
    fn to_py(&self, py: pyo3::Python<'_>) -> pyo3::PyObject {
        py.None()
    }
}

/// A set of sorted Events with the same tracking id.
#[derive(Default)]
pub struct EventSeries {
    /// Events that comprise the Series.
    pub events: Vec<Event>,
}

impl EventSeries {
    /// Encode the EventSeries into a json object.
    pub fn to_json(&self) -> Result<serde_json::Value> {
        let mut events = Vec::<serde_json::Value>::new();
        self.events.iter().try_for_each(|e| -> Result<()> {
            events.push(e.to_json()?);
            Ok(())
        })?;
        Ok(serde_json::Value::Array(events))
    }

    /// Create an EventSeries from a json string.
    pub(crate) fn from_json(line: String) -> Result<EventSeries> {
        let mut series = EventSeries::default();

        let mut series_js: Vec<serde_json::Value> = serde_json::from_str(line.as_str())
            .map_err(|e| anyhow!("Failed to parse json series at line {line}: {e}"))?;

        for obj in series_js.drain(..) {
            let event = serde_json::from_value(obj)?;
            series.events.push(event);
        }
        Ok(series)
    }
}

#[cfg(feature = "test-events")]
pub mod test {
    use super::*;
    use crate::event_section;

    #[event_section(SectionId::Common)]
    #[derive(Default)]
    pub struct TestEvent {
        pub field0: Option<u64>,
        pub field1: Option<u64>,
        pub field2: Option<u64>,
    }

    impl EventFmt for TestEvent {
        fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> std::fmt::Result {
            write!(
                f,
                "field0: {:?} field1: {:?} field2: {:?}",
                self.field0, self.field1, self.field2
            )
        }
    }
}

#[cfg(feature = "test-events")]
pub use test::*;
