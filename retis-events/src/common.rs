use std::fmt;

use crate::*;

#[event_type]
pub struct MachineInfo {
    pub kernel_release: String,
    pub kernel_version: String,
    pub hardware_name: String,
}

/// Startup event section. Contains global information about a collection as a
/// whole, with data gathered at collection startup time.
#[event_section]
pub struct StartupEvent {
    /// Retis version used while collecting events.
    pub retis_version: String,
    /// CLOCK_MONOTONIC offset in regards to local machine time.
    pub clock_monotonic_offset: TimeSpec,
    /// Machine information retrieved while collecting events.
    pub machine: MachineInfo,
}

impl EventFmt for StartupEvent {
    fn event_fmt(&self, f: &mut Formatter, d: &DisplayFormat) -> fmt::Result {
        let sep = if d.multiline { "\n" } else { " " };

        write!(f, "Retis version {}", self.retis_version)?;

        write!(
            f,
            "{sep}Machine info {} {} {}",
            self.machine.kernel_release, self.machine.kernel_version, self.machine.hardware_name
        )?;

        Ok(())
    }
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
