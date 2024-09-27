use std::fmt;

use super::*;
use crate::{event_section, Formatter};

/// Sk reset reason event section.
#[event_section(SectionId::SkResetReason)]
pub struct SkResetReasonEvent {
    /// Reason why a socket sent a reset. Only reported from specific functions.
    /// See `enum sk_rst_reason` in the kernel.
    pub reset_reason: String,
}

impl EventFmt for SkResetReasonEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(f, "(rst reason {})", self.reset_reason)
    }
}
