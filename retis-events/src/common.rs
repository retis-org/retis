use std::fmt;

use crate::{
    helpers::{file_rotate::RotationPolicy, time::*},
    *,
};

/// Startup event section. Contains global information about a collection as a
/// whole, with data gathered at collection startup time.
#[event_section]
pub struct StartupEvent {
    /// Retis version used while collecting events.
    pub retis_version: String,
    /// CLOCK_MONOTONIC offset in regards to local machine time.
    pub clock_monotonic_offset: TimeSpec,
    /// Information about the split file, if any.
    pub split_file: Option<SplitFile>,
}

impl EventFmt for StartupEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(f, "Events collected using Retis {}", self.retis_version)?;

        if let Some(split) = &self.split_file {
            write!(f, ", reading file id {}", split.id)?;
        }

        Ok(())
    }
}

/// Information about a partial event file generated while splitting the full
/// collection into multiple files.
#[event_type]
pub struct SplitFile {
    /// Split file id in the set of split files; first one is "0".
    pub id: u32,
    /// Rotation policy used when generating files.
    pub policy: RotationPolicy,
}

/// Information about a given task.
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
#[event_section]
#[derive(Default)]
pub struct CommonEvent {
    /// Timestamp of when the event was generated.
    pub timestamp: u64,
    /// SMP processor id.
    pub smp_id: Option<u32>,
    /// Information about the task linked to the event.
    pub task: Option<TaskEvent>,
}

impl EventFmt for CommonEvent {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result {
        write!(
            f,
            "{}",
            format_date_time(format.time_format, self.timestamp, format.monotonic_offset)
        )?;

        if let Some(smp_id) = self.smp_id {
            write!(f, " ({smp_id})")?;
        }

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
