use std::fmt;

use super::*;
use crate::event_section;

#[event_section]
pub(crate) struct UserEvent {
    /// Probe type: for now only "usdt" is supported.
    pub(crate) probe_type: String,
    /// Symbol name associated with the event (i.e. which probe generated the
    /// event).
    pub(crate) symbol: String,
    /// Instruction pointer: address of the symbol associted with the event.
    pub(crate) ip: u64,
    /// Path of the binary associated with the event.
    pub(crate) path: String,
    /// Process id.
    pub(crate) pid: i32,
    /// Thread id.
    pub(crate) tid: i32,
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
