#![allow(dead_code)] // FIXME

use std::fmt;

use crate::core::kernel;

/// Probe types supported by this program. This is the main object given to
/// tracing APIs and it does contain everything needed to target a symbol in a
/// given running program.
pub(crate) enum Probe {
    Kprobe(kernel::Symbol),
    RawTracepoint(kernel::Symbol),
}

// Use mem::variant_count::<Probe>() when available in stable.
pub(crate) const PROBE_VARIANTS: usize = 2;

impl Probe {
    /// We do use probe types as indexes, the following makes it easy.
    pub(crate) fn as_key(&self) -> usize {
        match self {
            Probe::Kprobe(_) => 0,
            Probe::RawTracepoint(_) => 1,
        }
    }
}

/// Allow nice log messages.
impl fmt::Display for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Probe::Kprobe(symbol) => write!(f, "kprobe:{}", symbol),
            Probe::RawTracepoint(symbol) => write!(f, "raw_tracepoint:{}", symbol),
        }
    }
}
