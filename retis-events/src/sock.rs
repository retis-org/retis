use std::fmt;

use super::*;
use crate::Formatter;

/// Socket section.
#[event_section]
pub struct SockEvent {
    /// Data shared by all socket types.
    pub common: Option<SockCommonEvent>,
}

impl EventFmt for SockEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        if let Some(common) = &self.common {
            write!(
                f,
                "sock {} {} {}",
                common.inode, common.r#type, common.proto
            )?;
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
}
