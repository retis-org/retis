use std::fmt;

use crate::{file::rotate::RotationPolicy, helpers::time::*, *};

/// Machine information.
#[event_type]
pub struct MachineInfo {
    /// Kernel release.
    pub kernel_release: String,
    /// Kernel version.
    pub kernel_version: String,
    /// Hardware name.
    pub hardware_name: String,
}

/// Startup event section. Contains global information about a collection as a
/// whole, with data gathered at collection startup time.
#[event_section]
pub struct StartupEvent {
    /// Retis version used while collecting events.
    pub retis_version: String,
    /// Expanded command line used to invoke the application.
    pub cmdline: String,
    /// CLOCK_MONOTONIC offset in regards to local machine time.
    pub clock_monotonic_offset: TimeSpec,
    /// Machine information retrieved while collecting events.
    pub machine: MachineInfo,
    /// Information about the split file, if any.
    pub split_file: Option<SplitFile>,
}

impl EventFmt for StartupEvent {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result {
        let sep = if format.multiline { "\n" } else { " " };

        write!(f, "collected with Retis {}", self.retis_version)?;
        write!(
            f,
            "{sep}on machine {} {} {}",
            self.machine.kernel_release, self.machine.kernel_version, self.machine.hardware_name
        )?;

        if let Some(split) = &self.split_file {
            write!(f, "{sep}file id {}", split.id)?;
        }

        write!(f, "{sep}cmdline {}", self.cmdline)
    }
}

/// Split-file information
///
/// Information about a partial event file generated while splitting the full
/// collection into multiple files.
#[event_type]
pub struct SplitFile {
    /// Split file id in the set of split files; first one is "0".
    pub id: u32,
    /// Rotation policy used when generating files.
    pub policy: RotationPolicy,
}

/// Task information.
#[event_type]
#[derive(Default)]
pub struct TaskEvent {
    /// Process ID.
    pub pid: i32,
    /// Thread group ID.
    pub tgid: i32,
    /// Task name.
    pub comm: String,
}

/// Common section.
#[event_section]
#[derive(Default)]
pub struct CommonEvent {
    /// Timestamp.
    pub timestamp: u64,
    /// SMP processor ID.
    pub smp_id: Option<u32>,
    /// Linux task.
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
