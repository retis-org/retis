use std::fmt;

use crate::{event_section, event_type, *};

#[event_type]
#[derive(Default)]
pub struct TaskEvent {
    /// Process id.
    pub pid: i32,
    /// Thread group id.
    pub tgid: i32,
    /// Name of the current task.
    pub comm: String,
}

/// Common event section.
#[event_section("common")]
pub struct CommonEvent {
    /// Timestamp of when the event was generated.
    pub timestamp: u64,
    /// SMP processor id.
    pub smp_id: u32,
    pub task: Option<TaskEvent>,
}

impl EventFmt for CommonEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        write!(f, "{} ({})", self.timestamp, self.smp_id)?;

        if let Some(current) = &self.task {
            write!(f, " [{}] ", current.comm)?;
            if current.tgid != current.pid {
                write!(f, "{}/", current.pid)?;
            }
            write!(f, "{}", current.tgid)?;
        }

        Ok(())
    }
}
