use std::fmt;

use super::*;
use crate::Formatter;

/// Socket section.
///
/// FIXME: make inode / r#type / proto / state in an optional "core" struct.
#[derive(Default)]
#[event_section]
pub struct SockEvent {
    /// Data shared by all socket types.
    pub common: Option<SockCommonEvent>,
    /// Socket reset reason, see `enum sk_rst_reason` in Linux.
    pub reset_reason: Option<String>,
}

impl EventFmt for SockEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(f, "sock")?;

        if let Some(common) = &self.common {
            write!(
                f,
                " ({} {} {}) state {}",
                common.inode, common.r#type, common.proto, common.state
            )?;
        }

        if let Some(reset_reason) = &self.reset_reason {
            write!(f, " rst (reason {reset_reason})")?;
        }

        Ok(())
    }
}

/// Common socket event data, shared by all socket types.
#[derive(Default)]
#[event_type]
pub struct SockCommonEvent {
    /// Socket inode
    pub inode: u32,
    /// Type
    pub r#type: String,
    /// Protocol
    pub proto: String,
    /// State
    pub state: String,
}
