use anyhow::{bail, Result};
use nix::time::{clock_gettime, ClockId};

use crate::events::helpers::time::TimeSpec;

/// Returns the monotonic timestamp in nanoseconds.
pub(crate) fn monotonic_timestamp() -> Result<u64> {
    let monotonic = clock_gettime(ClockId::CLOCK_MONOTONIC)?;

    let ts = monotonic.tv_sec() * 1000000000 + monotonic.tv_nsec();
    if ts < 0 {
        bail!("Monotonic timestamp is negative: {ts}");
    }

    Ok(ts as u64)
}

/// Computes and returns the offset of CLOCK_MONOTONIC to the wall-clock time.
pub(crate) fn monotonic_clock_offset() -> Result<TimeSpec> {
    let realtime = clock_gettime(ClockId::CLOCK_REALTIME)?;
    let monotonic = clock_gettime(ClockId::CLOCK_MONOTONIC)?;
    let offset = realtime - monotonic;

    Ok(TimeSpec::new(offset.tv_sec(), offset.tv_nsec()))
}
