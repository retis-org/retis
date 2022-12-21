use std::fmt;

use anyhow::{bail, Result};

use super::kernel::KernelProbe;
use crate::core::kernel;

/// Probe types supported by this program. This is the main object given to
/// tracing APIs and it does contain everything needed to target a symbol in a
/// given running program.
pub(crate) enum Probe {
    Kprobe(KernelProbe),
    RawTracepoint(KernelProbe),
}

impl Probe {
    /// Create a new kprobe.
    pub(crate) fn kprobe(symbol: kernel::Symbol) -> Result<Probe> {
        match symbol {
            kernel::Symbol::Func(_) => Ok(Probe::Kprobe(KernelProbe::new(symbol)?)),
            kernel::Symbol::Event(_) => bail!("Symbol cannot be probed with a kprobe"),
        }
    }

    /// Create a new raw tracepoint.
    pub(crate) fn raw_tracepoint(symbol: kernel::Symbol) -> Result<Probe> {
        match symbol {
            kernel::Symbol::Event(_) => Ok(Probe::RawTracepoint(KernelProbe::new(symbol)?)),
            kernel::Symbol::Func(_) => bail!("Symbol cannot be probed with a raw tracepoint"),
        }
    }
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
