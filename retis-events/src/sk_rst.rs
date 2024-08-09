use std::fmt;

use super::*;
use crate::event_section;

/// Sk reset reason event section.
#[event_section(SectionId::CommonType)] // FIXME
pub struct SkbResetReasonEvent {
    /// Reason why a socket sent a reset. Only reported from specific functions.
    /// See `enum sk_rst_reason` in the kernel.
    pub reset_reason: String,
}

impl EventFmt for SkbResetReasonEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        write!(f, "(rst reason {})", self.reset_reason)
    }
}
