#![allow(dead_code)] // FIXME

use std::{collections::HashMap, fmt};

use anyhow::{anyhow, bail, Result};
use log::info;

#[cfg(not(test))]
use super::config::init_config_map;
use super::{config::ProbeConfig, inspect::inspect_symbol, kprobe, raw_tracepoint};
use crate::core::{
    events::bpf::BpfEvents,
    kernel::Symbol,
    probe::{self, Probe},
};

/// Kernel encapsulates all the information about a kernel probe (kprobe or tracepoint) needed to attach to it.
pub(crate) struct KernelProbe {
    /// Symbol name
    pub(crate) symbol: Symbol,
    /// Symbol address
    pub(crate) ksym: u64,
    /// Number of arguments
    pub(crate) nargs: u32,
    /// Holds the different offsets to known parameters.
    pub(super) config: ProbeConfig,
}

impl KernelProbe {
    pub(crate) fn new(symbol: Symbol) -> Result<Self> {
        let desc = inspect_symbol(&symbol)?;
        Ok(KernelProbe {
            symbol,
            ksym: desc.ksym,
            nargs: desc.nargs,
            config: desc.probe_cfg,
        })
    }
}

impl fmt::Display for KernelProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.symbol)
    }
}

/// Hook provided by modules for registering them on kernel probes.
#[derive(Clone)]
pub(crate) struct Hook {
    /// Hook BPF binary data.
    bpf_prog: &'static [u8],
    /// HashMap of maps names and their fd, for reuse by the hook.
    maps: HashMap<String, i32>,
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

/// Main object representing the kernel probes and providing an API for
/// consumers to register probes, hooks, maps, etc.
pub(crate) struct Kernel {
    /// Probes sets, one per probe type. Used to keep track of all non-specific
    /// probes.
    probes: [ProbeSet; probe::PROBE_VARIANTS],
    /// List of targeted probes, aka. probes running a specific set of hooks.
    /// Targeted probes only have one target to keep things reasonable.
    targeted_probes: [Vec<ProbeSet>; probe::PROBE_VARIANTS],
    maps: HashMap<String, i32>,
    hooks: Vec<Hook>,
    #[cfg(not(test))]
    config_map: libbpf_rs::Map,
}

// Keep in sync with their BPF counterparts in bpf/include/common.h
pub(crate) const PROBE_MAX: usize = 128; // TODO add checks on probe registration.
pub(super) const HOOK_MAX: usize = 10;

struct ProbeSet {
    builder: Box<dyn ProbeBuilder>,
    targets: HashMap<String, Probe>,
    hooks: Vec<Hook>,
}

impl ProbeSet {
    fn new(builder: Box<dyn ProbeBuilder>) -> ProbeSet {
        ProbeSet {
            builder,
            targets: HashMap::new(),
            hooks: Vec::new(),
        }
    }
}

impl Kernel {
    pub(crate) fn new(events: &BpfEvents) -> Result<Kernel> {
        // Keep synced with the order of Probe::into::<usize>()!
        let probes: [ProbeSet; probe::PROBE_VARIANTS] = [
            ProbeSet::new(Box::new(kprobe::KprobeBuilder::new())),
            ProbeSet::new(Box::new(raw_tracepoint::RawTracepointBuilder::new())),
        ];
        let targeted_probes: [Vec<ProbeSet>; probe::PROBE_VARIANTS] = [Vec::new(), Vec::new()];

        // When testing the kernel object is not modified later to reuse the
        // config map is this map is hidden.
        #[allow(unused_mut)]
        let mut kernel = Kernel {
            probes,
            targeted_probes,
            maps: HashMap::new(),
            hooks: Vec::new(),
            #[cfg(not(test))]
            config_map: init_config_map()?,
        };

        #[cfg(not(test))]
        kernel
            .maps
            .insert("config_map".to_string(), kernel.config_map.fd());
        kernel
            .maps
            .insert("events_map".to_string(), events.map_fd());

        Ok(kernel)
    }

    /// Request to attach a probe of type r#type to a `Probe`.
    ///
    /// ```
    /// let symbol = kernel::Symbol::from_name("kfree_skb_reason").unwrap();
    /// kernel.add_probe(Probe::kprobe(symbol).unwrap()).unwrap();
    ///
    /// let symbol = kernel::Symbol::from_name("skb:kfree_skb").unwrap();
    /// kernel.add_probe(Probe::raw_tracepoint(symbol).unwrap()).unwrap();
    /// ```
    pub(crate) fn add_probe(&mut self, probe: Probe) -> Result<()> {
        let key = match &probe {
            Probe::Kprobe(probe) | Probe::RawTracepoint(probe) => probe.symbol.name(),
        };

        // First check if it is already in the generic probe list.
        let probe_set = &mut self.probes[probe.as_key()];
        if probe_set.targets.contains_key(&key) {
            return Ok(());
        }

        // Then if it is already in the targeted probe list.
        let tgt_set = &mut self.targeted_probes[probe.as_key()];
        for set in tgt_set.iter_mut() {
            if set.targets.get(&key).is_some() {
                return Ok(());
            }
        }

        probe_set.targets.insert(key, probe);
        Ok(())
    }

    /// Request to reuse a map fd. Useful for sharing maps across probes, for
    /// configuration, event reporting, or other use cases.
    ///
    /// ```
    /// kernel.reuse_map("config", fd).unwrap();
    /// ```
    pub(crate) fn reuse_map(&mut self, name: &str, fd: i32) -> Result<()> {
        let name = name.to_string();

        if self.maps.contains_key(&name) {
            bail!("Map {} already reused, or name is conflicting", name);
        }

        self.maps.insert(name, fd);
        Ok(())
    }

    /// Request a hook to be attached to all probes.
    ///
    /// ```
    /// mod hook {
    ///     include!("bpf/.out/hook.rs");
    /// }
    ///
    /// [...]
    ///
    /// kernel.register_hook(Hook::from(hook::DATA))?;
    /// ```
    pub(crate) fn register_hook(&mut self, hook: Hook) -> Result<()> {
        let mut max: usize = 0;
        for tgt_set in self.targeted_probes.iter_mut() {
            for set in tgt_set.iter_mut() {
                if max < set.hooks.len() {
                    max = set.hooks.len();
                }
            }
        }
        if self.hooks.len() + max == HOOK_MAX {
            bail!("Hook list is already full");
        }

        self.hooks.push(hook);
        Ok(())
    }

    /// Request a hook to be attached to a specific `Probe`.
    ///
    /// ```
    /// mod hook {
    ///     include!("bpf/.out/hook.rs");
    /// }
    ///
    /// [...]
    ///
    /// let symbol = kernel::Symbol::from_name("kfree_skb_reason").unwrap();
    /// kernel.register_hook_to(hook::DATA, symbol.to_kprobe().unwrap()).unwrap();
    /// ```
    pub(crate) fn register_hook_to(&mut self, hook: Hook, probe: Probe) -> Result<()> {
        let key = match &probe {
            Probe::Kprobe(probe) | Probe::RawTracepoint(probe) => probe.symbol.name(),
        };

        // First check if the target isn't already registered to the generic
        // probes list. If so, remove it from there.
        let probe_set = &mut self.probes[probe.as_key()];
        probe_set.targets.remove(&key);

        // Now check if we already have a targeted probe for this. If so, append
        // the new hook to it.
        let tgt_set = &mut self.targeted_probes[probe.as_key()];
        for set in tgt_set.iter_mut() {
            if set.targets.get(&key).is_some() {
                if self.hooks.len() + set.hooks.len() == HOOK_MAX {
                    bail!("Hook list is already full");
                }
                set.hooks.push(hook);
                return Ok(());
            }
        }

        // New target, let's build a new probe set.
        let mut set = ProbeSet::new(match probe {
            Probe::Kprobe(_) => Box::new(kprobe::KprobeBuilder::new()),
            Probe::RawTracepoint(_) => Box::new(raw_tracepoint::RawTracepointBuilder::new()),
        });

        set.targets.insert(key, probe);

        if self.hooks.len() == HOOK_MAX {
            bail!("Hook list is already full");
        }
        set.hooks.push(hook);

        tgt_set.push(set);
        Ok(())
    }

    /// Attach all probes.
    pub(crate) fn attach(&mut self) -> Result<()> {
        // Take care of generic probes first.
        for set in self.probes.iter_mut() {
            Self::attach_set(
                set,
                #[cfg(not(test))]
                &mut self.config_map,
                self.maps.clone(),
                self.hooks.clone(),
            )?;
        }

        // Then take care of targeted probes.
        for tgt_probe in self.targeted_probes.iter_mut() {
            for set in tgt_probe.iter_mut() {
                let hooks = [set.hooks.clone(), self.hooks.clone()].concat();
                Self::attach_set(
                    set,
                    #[cfg(not(test))]
                    &mut self.config_map,
                    self.maps.clone(),
                    hooks,
                )?;
            }
        }

        Ok(())
    }

    fn attach_set(
        set: &mut ProbeSet,
        #[cfg(not(test))] config_map: &mut libbpf_rs::Map,
        maps: HashMap<String, i32>,
        hooks: Vec<Hook>,
    ) -> Result<()> {
        if set.targets.is_empty() {
            return Ok(());
        }

        // Initialize the probe builder, only once for all targets.
        let map_fds = maps.into_iter().collect();
        set.builder.init(map_fds, hooks)?;

        // Then handle all probes in the set.
        for (_, probe) in set.targets.iter() {
            // First load the probe configuration.
            #[cfg(not(test))]
            match probe {
                Probe::Kprobe(probe) | Probe::RawTracepoint(probe) => {
                    let config = unsafe { plain::as_bytes(&probe.config) };
                    config_map.update(
                        &probe.ksym.to_ne_bytes(),
                        config,
                        libbpf_rs::MapFlags::NO_EXIST,
                    )?;
                }
            }

            // Finally attach a probe to the target.
            info!("Attaching probe to {}", probe);
            set.builder.attach(probe)?;
        }

        Ok(())
    }
}

/// Trait representing the interface used to create and handle probes. We use a
/// trait here as we're supporting various attach types.
pub(super) trait ProbeBuilder {
    /// Allocate and return a new instance of the probe builder, with default
    /// values.
    fn new() -> Self
    where
        Self: Sized;
    /// Initialize the probe builder before attaching programs to probes. It
    /// takes an option vector of map fds so that maps can be reused and shared
    /// accross builders.
    fn init(&mut self, map_fds: Vec<(String, i32)>, hooks: Vec<Hook>) -> Result<()>;
    /// Attach a probe to a given target (function, tracepoint, etc).
    fn attach(&mut self, probe: &Probe) -> Result<()>;
}

pub(super) fn reuse_map_fds(
    open_obj: &libbpf_rs::OpenObject,
    map_fds: &[(String, i32)],
) -> Result<()> {
    for map in map_fds.iter() {
        open_obj
            .map(map.0.clone())
            .ok_or_else(|| anyhow!("Couldn't get map {}", map.0.clone()))?
            .reuse_fd(map.1)?;
    }
    Ok(())
}

pub(super) fn replace_hooks(fd: i32, hooks: &[Hook]) -> Result<Vec<libbpf_rs::Link>> {
    let mut links = Vec::new();

    for (i, hook) in hooks.iter().enumerate() {
        let target = format!("hook{}", i);

        let mut open_obj =
            libbpf_rs::ObjectBuilder::default().open_memory("hook", hook.bpf_prog)?;

        // We have to explicitly use a Vec below to avoid having an unknown size
        // at build time.
        let map_fds: Vec<(String, i32)> = hook.maps.clone().into_iter().collect();
        reuse_map_fds(&open_obj, &map_fds)?;

        let open_prog = open_obj
            .prog_mut("hook")
            .ok_or_else(|| anyhow!("Couldn't get hook program"))?;

        open_prog.set_prog_type(libbpf_rs::ProgramType::Ext);
        open_prog.set_attach_target(fd, Some(target))?;

        let mut obj = open_obj.load()?;
        links.push(
            obj.prog_mut("hook")
                .ok_or_else(|| anyhow!("Couldn't get hook program"))?
                .attach_trace()?,
        );
    }

    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Dummy hook.
    const HOOK: &[u8] = &[0];

    macro_rules! kprobe {
        ($target:literal) => {
            Probe::Kprobe(KernelProbe::new(Symbol::from_name($target).unwrap()).unwrap())
        };
    }

    macro_rules! raw_tp {
        ($target:literal) => {
            Probe::RawTracepoint(KernelProbe::new(Symbol::from_name($target).unwrap()).unwrap())
        };
    }

    #[test]
    fn add_probe() {
        let events = BpfEvents::new().unwrap();
        let mut kernel = Kernel::new(&events).unwrap();

        assert!(kernel.add_probe(kprobe!("kfree_skb_reason")).is_ok());
        assert!(kernel.add_probe(kprobe!("consume_skb")).is_ok());
        assert!(kernel.add_probe(kprobe!("consume_skb")).is_ok());

        assert!(kernel.add_probe(raw_tp!("skb:kfree_skb")).is_ok());
        assert!(kernel.add_probe(raw_tp!("skb:kfree_skb")).is_ok());
    }

    #[test]
    fn register_hooks() {
        let events = BpfEvents::new().unwrap();
        let mut kernel = Kernel::new(&events).unwrap();

        assert!(kernel.register_hook(Hook::from(HOOK)).is_ok());
        assert!(kernel.register_hook(Hook::from(HOOK)).is_ok());

        assert!(kernel
            .register_hook_to(Hook::from(HOOK), kprobe!("kfree_skb_reason"))
            .is_ok());
        assert!(kernel.add_probe(kprobe!("kfree_skb_reason")).is_ok());

        assert!(kernel.add_probe(raw_tp!("skb:kfree_skb")).is_ok());
        assert!(kernel
            .register_hook_to(Hook::from(HOOK), raw_tp!("skb:kfree_skb"))
            .is_ok());
        assert!(kernel
            .register_hook_to(Hook::from(HOOK), raw_tp!("skb:kfree_skb"))
            .is_ok());

        for _ in 0..HOOK_MAX - 4 {
            assert!(kernel.register_hook(Hook::from(HOOK)).is_ok());
        }

        // We should hit the hook limit here.
        assert!(kernel.register_hook(Hook::from(HOOK)).is_err());

        assert!(kernel
            .register_hook_to(Hook::from(HOOK), kprobe!("kfree_skb_reason"))
            .is_ok());

        // We should hit the hook limit here as well.
        assert!(kernel
            .register_hook_to(Hook::from(HOOK), kprobe!("kfree_skb_reason"))
            .is_err());
        assert!(kernel
            .register_hook_to(Hook::from(HOOK), raw_tp!("skb:kfree_skb"))
            .is_err());
    }

    #[test]
    fn reuse_map() {
        let events = BpfEvents::new().unwrap();
        let mut kernel = Kernel::new(&events).unwrap();

        assert!(kernel.reuse_map("config", 0).is_ok());
        assert!(kernel.reuse_map("event", 0).is_ok());
        assert!(kernel.reuse_map("event", 0).is_err());
    }
}
