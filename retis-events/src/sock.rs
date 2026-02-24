use std::fmt;

use super::*;
use crate::Formatter;

/// Socket section.
///
/// FIXME: make inode / r#type / proto / state in an optional "core" struct.
#[derive(Default)]
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
    /// Socket reset reason, see `enum sk_rst_reason`.
    pub reset_reason: Option<String>,
}

impl EventFmt for SockEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(
            f,
            "sock ({} {} {}) state {}",
            self.inode, self.r#type, self.proto, self.state
        )?;

        if let Some(reset_reason) = &self.reset_reason {
            write!(f, " rst {reset_reason}")?;
        }

        Ok(())
    }
}
