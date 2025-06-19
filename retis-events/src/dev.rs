use std::fmt;

use super::*;
use crate::{event_section, Formatter};

/// Skb drop event section.
#[derive(Default)]
#[event_section(SectionId::Dev)]
pub struct DevEvent {
    /// Net device name associated with the packet, from `dev->name`.
    pub name: String,
    /// Net device ifindex associated with the packet, from `dev->ifindex`.
    pub ifindex: u32,
    /// Index if the net device the packet arrived on, from `skb->skb_iif`.
    pub rx_ifindex: Option<u32>,
}

impl EventFmt for DevEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(f, "if {}", self.ifindex)?;

        if !self.name.is_empty() {
            write!(f, " ({})", self.name)?;
        }

        if let Some(rx_ifindex) = self.rx_ifindex {
            write!(f, " rxif {rx_ifindex}")?;
        }

        Ok(())
    }
}
