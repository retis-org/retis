use std::{
    collections::{HashMap, HashSet},
    fmt, mem,
    os::fd::RawFd,
};

use anyhow::{bail, Result};

use super::kernel::KernelProbe;
use super::user::UsdtProbe;
use crate::core::kernel;

/// Probe types supported by this program. This is the main object given to
/// tracing APIs and it does contain everything needed to target a symbol in a
/// given running program.
#[derive(Clone)]
pub(crate) enum ProbeType {
    Kprobe(KernelProbe),
    #[allow(dead_code)]
    Kretprobe(KernelProbe),
    RawTracepoint(KernelProbe),
    #[allow(dead_code)]
    Usdt(UsdtProbe),
}

/// Probe options, to toggle opt-in/out features.
#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) enum ProbeOption {
    StackTrace,
    NoGenericHook,
}

/// Represents a probe we can install in a target (kernel, user space program,
/// etc). It can be of various underlying types, which can be retrieved using
/// `let r#type = probe.r#type();`
#[derive(Clone)]
pub(crate) struct Probe {
    r#type: ProbeType,
    pub(super) hooks: Vec<Hook>,
    pub(super) options: HashSet<ProbeOption>,
}

impl Probe {
    pub(super) fn from(r#type: ProbeType) -> Probe {
        Probe {
            r#type,
            hooks: Vec::new(),
            options: HashSet::new(),
        }
    }

    /// Create a new kprobe.
    pub(crate) fn kprobe(symbol: kernel::Symbol) -> Result<Probe> {
        let r#type = match symbol {
            kernel::Symbol::Func(_) => ProbeType::Kprobe(KernelProbe::new(symbol)?),
            kernel::Symbol::Event(_) => bail!("Symbol cannot be probed with a kprobe"),
        };
        Ok(Probe::from(r#type))
    }

    /// Create a new kretprobe
    pub(crate) fn kretprobe(symbol: kernel::Symbol) -> Result<Probe> {
        let r#type = match symbol {
            kernel::Symbol::Func(_) => ProbeType::Kretprobe(KernelProbe::new(symbol)?),
            kernel::Symbol::Event(_) => bail!("Symbol cannot be probed with a kretprobe"),
        };
        Ok(Probe::from(r#type))
    }

    /// Create a new raw tracepoint.
    pub(crate) fn raw_tracepoint(symbol: kernel::Symbol) -> Result<Probe> {
        let r#type = match symbol {
            kernel::Symbol::Event(_) => ProbeType::RawTracepoint(KernelProbe::new(symbol)?),
            kernel::Symbol::Func(_) => bail!("Symbol cannot be probed with a raw tracepoint"),
        };
        Ok(Probe::from(r#type))
    }

    /// Create a new usdt probe.
    pub(crate) fn usdt(usdt_probe: UsdtProbe) -> Result<Probe> {
        let r#type = ProbeType::Usdt(usdt_probe);
        Ok(Probe::from(r#type))
    }

    /// Retrieve a reference to the underlying ProbeType.
    #[allow(dead_code)]
    pub(crate) fn r#type(&self) -> &ProbeType {
        &self.r#type
    }

    /// Retrieve a mutable reference to the underlying ProbeType.
    #[allow(dead_code)]
    pub(crate) fn type_mut(&mut self) -> &mut ProbeType {
        &mut self.r#type
    }

    /// Use the underlying symbol to get its name and use it as a key which can
    /// be used to differenciate between probes.
    pub(crate) fn key(&self) -> String {
        format!("{self}")
    }

    /// We do use probe types as indexes, the following makes it easy.
    pub(crate) fn type_key(&self) -> usize {
        match self.r#type() {
            ProbeType::Kprobe(_) => 0,
            ProbeType::Kretprobe(_) => 1,
            ProbeType::RawTracepoint(_) => 2,
            ProbeType::Usdt(_) => 3,
        }
    }

    /// Append a new targeted hook to the probe.
    pub(crate) fn add_hook(&mut self, hook: Hook) -> Result<()> {
        if let ProbeType::Usdt(_) = self.r#type() {
            if !self.hooks.is_empty() {
                bail!("USDT probes only support a single hook");
            }
        }

        self.hooks.push(hook);
        Ok(())
    }

    /// Returns the number of hooks installed on the probe.
    pub(crate) fn hooks_len(&self) -> usize {
        self.hooks.len()
    }

    /// Is this probe generic (aimed at hosting generic hooks only)?
    #[cfg(not(test))]
    pub(crate) fn is_generic(&self) -> bool {
        self.hooks.is_empty() && self.supports_generic_hooks()
    }

    /// Are generic hooks supported by the of probe?
    pub(crate) fn supports_generic_hooks(&self) -> bool {
        !matches!(self.r#type(), ProbeType::Usdt(_))
            && !self.options.contains(&ProbeOption::NoGenericHook)
    }

    /// Set a probe option.
    pub(crate) fn set_option(&mut self, option: ProbeOption) -> Result<()> {
        self.options.insert(option);
        Ok(())
    }

    /// Get all probe's options.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn options(&self) -> Vec<ProbeOption> {
        self.options.clone().into_iter().collect()
    }

    /// Reuse a map in all the probe's hooks.
    pub(crate) fn reuse_map(&mut self, name: &str, fd: RawFd) -> Result<()> {
        self.hooks
            .iter_mut()
            .try_for_each(|h| h.reuse_map(name, fd).map(|_| ()))
    }

    /// Merge two probes into the current one. The second probe can't be used
    /// after this.
    pub(crate) fn merge(&mut self, other: &mut Probe) -> Result<()> {
        if mem::discriminant(self.r#type()) != mem::discriminant(other.r#type()) {
            bail!("Can't merge two probe with a different underlying type");
        }

        // Merge options.
        // - ProbeOption::StackTrace: if any of the probes has it, it should be
        //   set in the resulting probe.
        // - ProbeOption::NoGenericHook: has to be set in both probes to be set in the
        //   resulting probe.
        if let Some(opt) = other.options.take(&ProbeOption::StackTrace) {
            self.options.insert(opt);
        }
        if !other.options.contains(&ProbeOption::NoGenericHook) {
            self.options.remove(&ProbeOption::NoGenericHook);
        }

        // Merge hooks.
        self.hooks.append(&mut other.hooks);
        Ok(())
    }
}

/// Allow nice log messages.
impl fmt::Display for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.r#type() {
            ProbeType::Kprobe(symbol) => write!(f, "kprobe:{symbol}"),
            ProbeType::Kretprobe(symbol) => write!(f, "kretprobe:{symbol}"),
            ProbeType::RawTracepoint(symbol) => write!(f, "tp:{symbol}"),
            ProbeType::Usdt(symbol) => write!(f, "usdt {symbol}"),
        }
    }
}

/// Hook provided by modules for registering them on kernel probes.
#[derive(Clone)]
pub(crate) struct Hook {
    /// Hook BPF binary data.
    pub(super) bpf_prog: &'static [u8],
    /// HashMap of maps names and their fd, for reuse by the hook.
    pub(super) maps: HashMap<String, RawFd>,
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
    pub(crate) fn reuse_map(&mut self, name: &str, fd: RawFd) -> Result<&mut Self> {
        let name = name.to_string();

        if self.maps.contains_key(&name) {
            bail!("Map {} already reused, or name is conflicting", name);
        }

        self.maps.insert(name, fd);
        Ok(self)
    }
}
