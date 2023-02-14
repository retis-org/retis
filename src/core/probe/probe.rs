use std::{collections::HashMap, fmt};

use anyhow::{bail, Result};

use super::kernel::KernelProbe;
use super::user::UsdtProbe;
use crate::core::kernel;

/// Probe types supported by this program. This is the main object given to
/// tracing APIs and it does contain everything needed to target a symbol in a
/// given running program.
pub(crate) enum Probe {
    Kprobe(KernelProbe),
    #[allow(dead_code)]
    Kretprobe(KernelProbe),
    RawTracepoint(KernelProbe),
    #[allow(dead_code)]
    Usdt(UsdtProbe),
}

impl Probe {
    /// Create a new kprobe.
    pub(crate) fn kprobe(symbol: kernel::Symbol) -> Result<Probe> {
        match symbol {
            kernel::Symbol::Func(_) => Ok(Probe::Kprobe(KernelProbe::new(symbol)?)),
            kernel::Symbol::Event(_) => bail!("Symbol cannot be probed with a kprobe"),
        }
    }

    /// Create a new kretprobe
    #[allow(dead_code)]
    pub(crate) fn kretprobe(symbol: kernel::Symbol) -> Result<Probe> {
        match symbol {
            kernel::Symbol::Func(_) => Ok(Probe::Kretprobe(KernelProbe::new(symbol)?)),
            kernel::Symbol::Event(_) => bail!("Symbol cannot be probed with a kretprobe"),
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
pub(crate) const PROBE_VARIANTS: usize = 4;

impl Probe {
    /// We do use probe types as indexes, the following makes it easy.
    pub(crate) fn as_key(&self) -> usize {
        match self {
            Probe::Kprobe(_) => 0,
            Probe::Kretprobe(_) => 1,
            Probe::RawTracepoint(_) => 2,
            Probe::Usdt(_) => 3,
        }
    }
}

/// Allow nice log messages.
impl fmt::Display for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Probe::Kprobe(symbol) => write!(f, "kprobe:{symbol}"),
            Probe::Kretprobe(symbol) => write!(f, "kretprobe:{symbol}"),
            Probe::RawTracepoint(symbol) => write!(f, "raw_tracepoint:{symbol}"),
            Probe::Usdt(symbol) => write!(f, "usdt {symbol}"),
        }
    }
}

/// Hook provided by modules for registering them on kernel probes.
#[derive(Clone)]
pub(crate) struct Hook {
    /// Hook BPF binary data.
    pub(super) bpf_prog: &'static [u8],
    /// HashMap of maps names and their fd, for reuse by the hook.
    pub(super) maps: HashMap<String, i32>,
}

impl Hook {
    /// Create a new hook given a BPF binary data.
    pub(crate) fn from(bpf_prog: &'static [u8]) -> Hook {
        Hook {
            bpf_prog,
            maps: HashMap::new(),
        }
    }

    /// Request to reuse a map specifically in the hook. For maps being globally
    /// reused please use Kernel::reuse_map() instead.
    pub(crate) fn reuse_map(&mut self, name: &str, fd: i32) -> Result<&mut Self> {
        let name = name.to_string();

        if self.maps.contains_key(&name) {
            bail!("Map {} already reused, or name is conflicting", name);
        }

        self.maps.insert(name, fd);
        Ok(self)
    }
}
