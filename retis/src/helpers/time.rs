use anyhow::Result;
use nix::time::{clock_gettime, ClockId};

use crate::events::TimeSpec;

/// Computes and returns the offset of CLOCK_MONOTONIC to the wall-clock time.
pub(crate) fn monotonic_clock_offset() -> Result<TimeSpec> {
    let realtime = clock_gettime(ClockId::CLOCK_REALTIME)?;
    let monotonic = clock_gettime(ClockId::CLOCK_MONOTONIC)?;
    let offset = realtime - monotonic;

    Ok(TimeSpec::new(offset.tv_sec(), offset.tv_nsec()))
}
