#![allow(dead_code)] // FIXME
use std::collections::HashMap;

use anyhow::{bail, Result};
use log::{debug, info};

#[cfg(not(test))]
use super::kernel::config::init_config_map;
use super::*;
use super::{
    builder::ProbeBuilder,
    kernel::{kprobe, kretprobe, raw_tracepoint},
    user::usdt,
};
use crate::core::filters::Filter;

// Keep in sync with their BPF counterparts in bpf/include/common.h
pub(crate) const PROBE_MAX: usize = 128; // TODO add checks on probe registration.
pub(super) const HOOK_MAX: usize = 10;

/// ProbeManager is the main object providing an API for consumers to register probes, hooks, maps,
/// etc.
pub(crate) struct ProbeManager {
    /// Dynamic ProbeSets, one per probe type. Used to keep track of all non-specific
    /// probes.
    dynamic_probes: [ProbeSet; PROBE_VARIANTS],

    /// Dynamic Hooks. A list of hooks to be attached to all dynamic probes.
    dynamic_hooks: Vec<Hook>,

    /// Dynamic Filters. A list of filters to be attached to all dynamic probes.
    filters: Vec<Filter>,

    /// Dynamic probes requires a map that provides extra information at runtime. This is that map.
    #[cfg(not(test))]
    config_map: libbpf_rs::Map,

    /// List of options to enable/disable additional probes behavior.
    options: Vec<ProbeOption>,

    // Targeted probes.
    /// List of targeted probes, aka. probes running a specific set of hooks.
    /// Targeted probes only have one target to keep things reasonable.
    targeted_probes: [Vec<ProbeSet>; PROBE_VARIANTS],

    // Common (both dynamic and targetted) data.
    /// Maps. HashMap of map names and file descriptors
    maps: HashMap<String, i32>,
}

impl ProbeManager {
    pub(crate) fn new() -> Result<ProbeManager> {
        // Keep synced with the order of Probe::into::<usize>()!
        let dynamic_probes: [ProbeSet; probe::PROBE_VARIANTS] = [
            ProbeSet::new(Box::new(kprobe::KprobeBuilder::new()), true),
            ProbeSet::new(Box::new(kretprobe::KretprobeBuilder::new()), true),
            ProbeSet::new(Box::new(raw_tracepoint::RawTracepointBuilder::new()), true),
            ProbeSet::new(Box::new(usdt::UsdtBuilder::new()), false),
        ];
        let targeted_probes: [Vec<ProbeSet>; probe::PROBE_VARIANTS] = Default::default();

        // When testing the kernel object is not modified later to reuse the
        // config map is this map is hidden.
        #[allow(unused_mut)]
        let mut mgr = ProbeManager {
            dynamic_probes,
            dynamic_hooks: Vec::new(),
            filters: Vec::new(),
            #[cfg(not(test))]
            config_map: init_config_map()?,
            options: Vec::new(),
            targeted_probes,
            maps: HashMap::new(),
        };

        #[cfg(not(test))]
        mgr.maps
            .insert("config_map".to_string(), mgr.config_map.fd());

        Ok(mgr)
    }

    /// Add a probe option for later fixup during the attach phase
    pub(crate) fn add_probe_opt(&mut self, opt: ProbeOption) {
        self.options.push(opt);
    }

    /// Request to attach a dynamic probe to `Probe`.
    ///
    /// ```
    /// let symbol = kernel::Symbol::from_name("kfree_skb_reason").unwrap();
    /// mgr.add_probe(Probe::kprobe(symbol).unwrap()).unwrap();
    ///
    /// let symbol = kernel::Symbol::from_name("skb:kfree_skb").unwrap();
    /// mgr.add_probe(Probe::raw_tracepoint(symbol).unwrap()).unwrap();
    /// ```
    pub(crate) fn add_probe(&mut self, probe: Probe) -> Result<()> {
        let key = match &probe {
            Probe::Kprobe(probe) | Probe::Kretprobe(probe) | Probe::RawTracepoint(probe) => {
                probe.symbol.name()
            }
            Probe::Usdt(probe) => probe.name(),
        };

        // First check if it is already in the generic probe list.
        let probe_set = &mut self.dynamic_probes[probe.as_key()];
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
    /// mgr.reuse_map("config", fd).unwrap();
    /// ```
    pub(crate) fn reuse_map(&mut self, name: &str, fd: i32) -> Result<()> {
        let name = name.to_string();

        if self.maps.contains_key(&name) {
            bail!("Map {} already reused, or name is conflicting", name);
        }

        self.maps.insert(name, fd);
        Ok(())
    }

    /// Request a filter to be attached to all probes.
    ///
    /// ```
    /// mgr.register_filter(filter)?;
    /// ```
    pub(crate) fn register_filter(&mut self, filter: Filter) -> Result<()> {
        // Avoid duplicate filter types as any Filter variant should
        // be present only once
        if self
            .filters
            .iter()
            .any(|f| std::mem::discriminant(f) == std::mem::discriminant(&filter))
        {
            bail!("Tried to register multiple filters of the same type");
        }

        self.filters.push(filter);
        Ok(())
    }

    /// Request a hook to be attached to all kernel probes.
    ///
    /// ```
    /// mod hook {
    ///     include!("bpf/.out/hook.rs");
    /// }
    ///
    /// [...]
    ///
    /// mgr.register_kernel_hook(Hook::from(hook::DATA))?;
    /// ```
    pub(crate) fn register_kernel_hook(&mut self, hook: Hook) -> Result<()> {
        let mut max: usize = 0;
        for tgt_set in self.targeted_probes.iter_mut() {
            for set in tgt_set.iter_mut() {
                if max < set.hooks.len() {
                    max = set.hooks.len();
                }
            }
        }
        if self.dynamic_hooks.len() + max == HOOK_MAX {
            bail!("Hook list is already full");
        }

        self.dynamic_hooks.push(hook);
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
    /// mgr.register_hook_to(hook::DATA, Probe::kprobe(symbol).unwrap()).unwrap();
    /// ```
    pub(crate) fn register_hook_to(&mut self, hook: Hook, probe: Probe) -> Result<()> {
        let key = match &probe {
            Probe::Kprobe(probe) | Probe::Kretprobe(probe) | Probe::RawTracepoint(probe) => {
                probe.symbol.name()
            }
            Probe::Usdt(probe) => probe.name(),
        };

        // First check if the target isn't already registered to the generic
        // probes list. If so, remove it from there.
        let probe_set = &mut self.dynamic_probes[probe.as_key()];
        probe_set.targets.remove(&key);

        // Now check if we already have a targeted probe for this. If so, append
        // the new hook to it.
        let tgt_set = &mut self.targeted_probes[probe.as_key()];
        for set in tgt_set.iter_mut() {
            if set.targets.get(&key).is_some() {
                if let Probe::Usdt(_) = probe {
                    bail!("USDT probes only support a single hook")
                }
                if self.dynamic_hooks.len() + set.hooks.len() == HOOK_MAX {
                    bail!("Hook list is already full");
                }
                set.hooks.push(hook);
                return Ok(());
            }
        }

        // New target, let's build a new probe set.
        let mut set = match probe {
            Probe::Kprobe(_) => ProbeSet::new(Box::new(kprobe::KprobeBuilder::new()), true),
            Probe::Kretprobe(_) => {
                ProbeSet::new(Box::new(kretprobe::KretprobeBuilder::new()), true)
            }
            Probe::RawTracepoint(_) => {
                ProbeSet::new(Box::new(raw_tracepoint::RawTracepointBuilder::new()), true)
            }
            Probe::Usdt(_) => ProbeSet::new(Box::new(usdt::UsdtBuilder::new()), false),
        };

        set.targets.insert(key, probe);

        if self.dynamic_hooks.len() == HOOK_MAX {
            bail!("Hook list is already full");
        }
        set.hooks.push(hook);

        tgt_set.push(set);
        Ok(())
    }

    /// Attach all probes.
    pub(crate) fn attach(&mut self) -> Result<()> {
        // Take care of generic probes first.
        for set in self.dynamic_probes.iter_mut() {
            set.hooks = self.dynamic_hooks.clone();
            set.filters = self.filters.clone();
            set.attach(
                #[cfg(not(test))]
                &mut self.config_map,
                self.maps.clone(),
                #[cfg(not(test))]
                &self.options,
            )?;
        }

        // Then take care of targeted probes.
        for tgt_probe in self.targeted_probes.iter_mut() {
            for set in tgt_probe.iter_mut() {
                // Extend targeted hooks with dynamic ones.
                if set.supports_dynamic {
                    set.hooks.extend(self.dynamic_hooks.iter().cloned());
                    set.filters = self.filters.clone();
                }
                set.attach(
                    #[cfg(not(test))]
                    &mut self.config_map,
                    self.maps.clone(),
                    #[cfg(not(test))]
                    &self.options,
                )?;
            }
        }

        Ok(())
    }
}

struct ProbeSet {
    builder: Box<dyn ProbeBuilder>,
    targets: HashMap<String, Probe>,
    hooks: Vec<Hook>,
    filters: Vec<Filter>,
    supports_dynamic: bool,
}

impl ProbeSet {
    /// Creates a new empty ProbeSet.
    fn new(builder: Box<dyn ProbeBuilder>, supports_dynamic: bool) -> ProbeSet {
        ProbeSet {
            builder,
            targets: HashMap::new(),
            hooks: Vec::new(),
            filters: Vec::new(),
            supports_dynamic,
        }
    }

    /// Attach all the probes and hook in the ProbeSet.
    fn attach(
        &mut self,
        #[cfg(not(test))] config_map: &mut libbpf_rs::Map,
        maps: HashMap<String, i32>,
        #[cfg(not(test))] options: &[ProbeOption],
    ) -> Result<()> {
        if self.targets.is_empty() {
            return Ok(());
        }

        // Initialize the probe builder, only once for all targets.
        let map_fds = maps.into_iter().collect();
        self.builder
            .init(map_fds, self.hooks.clone(), self.filters.clone())?;

        // Then handle all probes in the set.
        for (_, probe) in self.targets.iter_mut() {
            // First load the probe configuration.
            #[cfg(not(test))]
            match probe {
                Probe::Kprobe(ref mut p)
                | Probe::Kretprobe(ref mut p)
                | Probe::RawTracepoint(ref mut p) => {
                    options.iter().for_each(|c| p.set_option(c));
                    let config = unsafe { plain::as_bytes(&p.config) };
                    config_map.update(&p.ksym.to_ne_bytes(), config, libbpf_rs::MapFlags::ANY)?;
                }
                _ => (),
            }

            // Finally attach a probe to the target.
            debug!("Attaching probe to {}", probe);
            self.builder.attach(probe)?;
        }

        // All probes loaded, issue an info log.
        info!("{} probe(s) loaded", self.targets.len());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::kernel::Symbol;

    // Dummy hook.
    const HOOK: &[u8] = &[0];

    macro_rules! kprobe {
        ($target:literal) => {
            Probe::kprobe(Symbol::from_name($target).unwrap()).unwrap()
        };
    }

    macro_rules! raw_tp {
        ($target:literal) => {
            Probe::raw_tracepoint(Symbol::from_name($target).unwrap()).unwrap()
        };
    }

    #[test]
    fn add_probe() {
        let mut mgr = ProbeManager::new().unwrap();

        assert!(mgr.add_probe(kprobe!("kfree_skb_reason")).is_ok());
        assert!(mgr.add_probe(kprobe!("consume_skb")).is_ok());
        assert!(mgr.add_probe(kprobe!("consume_skb")).is_ok());

        assert!(mgr.add_probe(raw_tp!("skb:kfree_skb")).is_ok());
        assert!(mgr.add_probe(raw_tp!("skb:kfree_skb")).is_ok());
    }

    #[test]
    fn register_hooks() {
        let mut mgr = ProbeManager::new().unwrap();

        assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_ok());
        assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_ok());

        assert!(mgr
            .register_hook_to(Hook::from(HOOK), kprobe!("kfree_skb_reason"))
            .is_ok());
        assert!(mgr.add_probe(kprobe!("kfree_skb_reason")).is_ok());

        assert!(mgr.add_probe(raw_tp!("skb:kfree_skb")).is_ok());
        assert!(mgr
            .register_hook_to(Hook::from(HOOK), raw_tp!("skb:kfree_skb"))
            .is_ok());
        assert!(mgr
            .register_hook_to(Hook::from(HOOK), raw_tp!("skb:kfree_skb"))
            .is_ok());

        for _ in 0..HOOK_MAX - 4 {
            assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_ok());
        }

        // We should hit the hook limit here.
        assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_err());

        assert!(mgr
            .register_hook_to(Hook::from(HOOK), kprobe!("kfree_skb_reason"))
            .is_ok());

        // We should hit the hook limit here as well.
        assert!(mgr
            .register_hook_to(Hook::from(HOOK), kprobe!("kfree_skb_reason"))
            .is_err());
        assert!(mgr
            .register_hook_to(Hook::from(HOOK), raw_tp!("skb:kfree_skb"))
            .is_err());
    }

    #[test]
    fn reuse_map() {
        let mut mgr = ProbeManager::new().unwrap();

        assert!(mgr.reuse_map("config", 0).is_ok());
        assert!(mgr.reuse_map("event", 0).is_ok());
        assert!(mgr.reuse_map("event", 0).is_err());
    }
}
