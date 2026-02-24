use std::fmt;

use super::*;
use crate::Formatter;

/// Socket section.
#[event_section]
pub struct SockEvent {
    /// Socket inode
    pub inode: u32,
    /// Type
    pub r#type: String,
    /// Protocol
    pub proto: String,
    /// State
    pub state: String,
}

impl EventFmt for SockEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(
            f,
            "sock ({} {} {}) state {}",
            self.inode, self.r#type, self.proto, self.state
        )
    }
}
