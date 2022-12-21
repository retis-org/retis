#![allow(dead_code)] // FIXME
use std::collections::HashMap;

use anyhow::{bail, Result};
use log::info;

#[cfg(not(test))]
use super::kernel::config::init_config_map;
use super::*;
use super::{
    builder::ProbeBuilder,
    kernel::{kprobe, raw_tracepoint},
};
use crate::core::events::bpf::BpfEvents;

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

    /// Dynamic probes requires a map that provides extra information at runtime. This is that map.
    #[cfg(not(test))]
    config_map: libbpf_rs::Map,

    // Targeted probes.
    /// List of targeted probes, aka. probes running a specific set of hooks.
    /// Targeted probes only have one target to keep things reasonable.
    targeted_probes: [Vec<ProbeSet>; PROBE_VARIANTS],

    // Common (both dynamic and targetted) data.
    /// Maps. HashMap of map names and file descriptors
    maps: HashMap<String, i32>,
}

impl ProbeManager {
    pub(crate) fn new(events: &BpfEvents) -> Result<ProbeManager> {
        // Keep synced with the order of Probe::into::<usize>()!
        let dynamic_probes: [ProbeSet; probe::PROBE_VARIANTS] = [
            ProbeSet::new(Box::new(kprobe::KprobeBuilder::new())),
            ProbeSet::new(Box::new(raw_tracepoint::RawTracepointBuilder::new())),
        ];
        let targeted_probes: [Vec<ProbeSet>; probe::PROBE_VARIANTS] = [Vec::new(), Vec::new()];
        // When testing the kernel object is not modified later to reuse the
        // config map is this map is hidden.
        let mut mgr = ProbeManager {
            dynamic_probes,
            dynamic_hooks: Vec::new(),
            #[cfg(not(test))]
            config_map: init_config_map()?,
            targeted_probes,
            maps: HashMap::new(),
        };

        #[cfg(not(test))]
        mgr.maps
            .insert("config_map".to_string(), mgr.config_map.fd());
        mgr.maps.insert("events_map".to_string(), events.map_fd());

        Ok(mgr)
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
            Probe::Kprobe(probe) | Probe::RawTracepoint(probe) => probe.symbol.name(),
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

    /// Request a hook to be attached to all probes.
    ///
    /// ```
    /// mod hook {
    ///     include!("bpf/.out/hook.rs");
    /// }
    ///
    /// [...]
    ///
    /// mgr.register_hook(Hook::from(hook::DATA))?;
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
            Probe::Kprobe(probe) | Probe::RawTracepoint(probe) => probe.symbol.name(),
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
                if self.dynamic_hooks.len() + set.hooks.len() == HOOK_MAX {
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
            set.attach(
                #[cfg(not(test))]
                &mut self.config_map,
                self.maps.clone(),
            )?;
        }

        // Then take care of targeted probes.
        for tgt_probe in self.targeted_probes.iter_mut() {
            for set in tgt_probe.iter_mut() {
                // Extend targeted hooks with dynamic ones.
                set.hooks.extend(self.dynamic_hooks.iter().cloned());
                set.attach(
                    #[cfg(not(test))]
                    &mut self.config_map,
                    self.maps.clone(),
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
}

impl ProbeSet {
    /// Creates a new empty ProbeSet.
    fn new(builder: Box<dyn ProbeBuilder>) -> ProbeSet {
        ProbeSet {
            builder,
            targets: HashMap::new(),
            hooks: Vec::new(),
        }
    }

    /// Attach all the probes and hook in the ProbeSet.
    fn attach(
        &mut self,
        #[cfg(not(test))] config_map: &mut libbpf_rs::Map,
        maps: HashMap<String, i32>,
    ) -> Result<()> {
        if self.targets.is_empty() {
            return Ok(());
        }

        // Initialize the probe builder, only once for all targets.
        let map_fds = maps.into_iter().collect();
        self.builder.init(map_fds, self.hooks.clone())?;

        // Then handle all probes in the set.
        for (_, probe) in self.targets.iter() {
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
            self.builder.attach(probe)?;
        }

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
        let events = BpfEvents::new().unwrap();
        let mut mgr = ProbeManager::new(&events).unwrap();

        assert!(mgr.add_probe(kprobe!("kfree_skb_reason")).is_ok());
        assert!(mgr.add_probe(kprobe!("consume_skb")).is_ok());
        assert!(mgr.add_probe(kprobe!("consume_skb")).is_ok());

        assert!(mgr.add_probe(raw_tp!("skb:kfree_skb")).is_ok());
        assert!(mgr.add_probe(raw_tp!("skb:kfree_skb")).is_ok());
    }

    #[test]
    fn register_hooks() {
        let events = BpfEvents::new().unwrap();
        let mut mgr = ProbeManager::new(&events).unwrap();

        assert!(mgr.register_hook(Hook::from(HOOK)).is_ok());
        assert!(mgr.register_hook(Hook::from(HOOK)).is_ok());

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
            assert!(mgr.register_hook(Hook::from(HOOK)).is_ok());
        }

        // We should hit the hook limit here.
        assert!(mgr.register_hook(Hook::from(HOOK)).is_err());

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
        let events = BpfEvents::new().unwrap();
        let mut mgr = ProbeManager::new(&events).unwrap();

        assert!(mgr.reuse_map("config", 0).is_ok());
        assert!(mgr.reuse_map("event", 0).is_ok());
        assert!(mgr.reuse_map("event", 0).is_err());
    }
}
