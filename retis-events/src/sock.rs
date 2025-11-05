use std::fmt;

use super::*;
use crate::Formatter;

/// Socket section.
#[event_section]
pub struct SockEvent {
    /// Socket inode
    pub inode: u32,
}

impl EventFmt for SockEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(f, "sock {}", self.inode)
    }
}
