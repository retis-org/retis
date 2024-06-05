use std::fmt;

use super::*;
use crate::event_section;

/// Skb drop event section.
#[event_section("skb-drop")]
pub struct SkbDropEvent {
    /// Sub-system who generated the below drop reason. None for core reasons.
    pub subsys: Option<String>,
    /// Reason why a packet was freed/dropped. Only reported from specific
    /// functions. See `enum skb_drop_reason` in the kernel.
    pub drop_reason: String,
}

impl EventFmt for SkbDropEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        match &self.subsys {
            None => write!(f, "drop (reason {})", self.drop_reason),
            Some(name) => write!(f, "drop (reason {name}/{})", self.drop_reason),
        }
    }
}
