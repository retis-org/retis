use std::fmt;

use super::*;
use crate::event_section;

#[event_section("userspace")]
pub struct UserEvent {
    /// Probe type: for now only "usdt" is supported.
    pub probe_type: String,
    /// Symbol name associated with the event (i.e. which probe generated the
    /// event).
    pub symbol: String,
    /// Instruction pointer: address of the symbol associted with the event.
    pub ip: u64,
    /// Path of the binary associated with the event.
    pub path: String,
    /// Process id.
    pub pid: i32,
    /// Thread id.
    pub tid: i32,
}

impl EventFmt for UserEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        write!(f, "[u] {}", self.symbol)?;
        if let Some((_, bin)) = self.path.rsplit_once('/') {
            write!(f, " ({})", bin)?;
        }
        Ok(())
    }
}
