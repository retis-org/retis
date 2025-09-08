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

use crate::{display::*, *};

/// Full event. Internal representation
#[derive(Default)]
#[event_section]
// For backwards compatibility reasons, we keep section names in kebab-case.
#[serde(rename_all = "kebab-case")]
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
    /// Packet section.
    pub packet: Option<PacketEvent>,
    /// Skb section.
    pub skb: Option<SkbEvent>,
    /// Net namespace section.
    pub netns: Option<NetnsEvent>,
    /// Net device section.
    pub dev: Option<DevEvent>,
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

        // Format the packet before the other fields, as this is the main focus
        // of Retis.
        if let Some(packet) = &self.packet {
            write!(f, "{sep}")?;
            packet.event_fmt(f, format)?;
        }

        // Special case the netns & dev sections, to make the output more
        // packed. Also the two are quite related and it makes sense to display
        // them on a single line.
        if let Some(netns) = &self.netns {
            write!(f, "{sep}")?;
            netns.event_fmt(f, format)?;
        }
        if let Some(dev) = &self.dev {
            write!(f, "{}", if self.netns.is_some() { ' ' } else { sep })?;
            dev.event_fmt(f, format)?;
        }

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
        .try_for_each(|field| match field {
            Some(field) if field.can_format(format) => {
                write!(f, "{sep}")?;
                field.event_fmt(f, format)
            }
            _ => Ok(()),
        })?;

        f.conf.reset_level();
        Ok(())
    }
}

/// A set of sorted Events with the same tracking id.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct EventSeries {
    /// Events that comprise the Series.
    pub events: Vec<Event>,
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
