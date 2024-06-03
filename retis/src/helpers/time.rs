use anyhow::{bail, Result};
use nix::time::{clock_gettime, ClockId};

/// Returns the monotonic timestamp in nanoseconds.
pub(crate) fn monotonic_timestamp() -> Result<u64> {
    let monotonic = clock_gettime(ClockId::CLOCK_MONOTONIC)?;

    let ts = monotonic.tv_sec() * 1000000000 + monotonic.tv_nsec();
    if ts < 0 {
        bail!("Monotonic timestamp is negative: {ts}");
    }

    Ok(ts as u64)
}
