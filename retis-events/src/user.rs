use std::fmt;

use super::*;
use crate::{event_section, Formatter};

/// Userspace section
#[event_section]
pub struct UserEvent {
    /// Probe type. For now only "usdt" is supported.
    pub probe_type: String,
    /// Symbol name. I.e. which probe generated the event.
    pub symbol: String,
    /// Instruction pointer. Address of the symbol associted with the event.
    pub ip: u64,
    /// Binary path.
    pub path: String,
    /// Process ID.
    pub pid: i32,
    /// Thread ID.
    pub tid: i32,
}

impl EventFmt for UserEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(f, "[u] {}", self.symbol)?;
        if let Some((_, bin)) = self.path.rsplit_once('/') {
            write!(f, " ({bin})")?;
        }
        Ok(())
    }
}
