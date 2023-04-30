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
pub(crate) const PROBE_MAX: usize = 128;
pub(super) const HOOK_MAX: usize = 10;

/// ProbeManager is the main object providing an API for consumers to register probes, hooks, maps,
/// etc.
pub(crate) struct ProbeManager {
    /// Generic probes (with no hook attached) & targeted probes (with hooks
    /// attached).
    probes: HashMap<String, Probe>,

    /// Generic hooks, meant to be attached to all probes supporting it..
    generic_hooks: Vec<Hook>,

    /// Filters, meant to be attached to all probes.
    filters: Vec<Filter>,

    /// List of global probe options to enable/disable additional probes behavior at a high level.
    global_probes_options: Vec<ProbeOption>,

    /// HashMap of map names and file descriptors, to be reused in all hooks.
    maps: HashMap<String, i32>,

    /// Dynamic probes requires a map that provides extra information at runtime. This is that map.
    #[cfg(not(test))]
    config_map: libbpf_rs::Map,

    /// Internal vec to store "used" probe builders, so we can keep a reference
    /// on them and keep probes loaded & installed.
    // TODO: should we change the builders to return the libbpf_rs::Link
    // directly?
    builders: Vec<Box<dyn ProbeBuilder>>,
}

impl ProbeManager {
    pub(crate) fn new() -> Result<ProbeManager> {
        // When testing the kernel object is not modified later to reuse the
        // config map is this map is hidden.
        #[allow(unused_mut)]
        let mut mgr = ProbeManager {
            probes: HashMap::new(),
            generic_hooks: Vec::new(),
            filters: Vec::new(),
            global_probes_options: Vec::new(),
            maps: HashMap::new(),
            #[cfg(not(test))]
            config_map: init_config_map()?,
            builders: Vec::new(),
        };

        #[cfg(not(test))]
        mgr.maps
            .insert("config_map".to_string(), mgr.config_map.fd());

        Ok(mgr)
    }

    /// Set a probe option for later fixup during the attach phase. A given
    /// option can only be set once as those are global and we can't decide
    /// which version to keep.
    pub(crate) fn set_probe_opt(&mut self, opt: ProbeOption) -> Result<()> {
        if self
            .global_probes_options
            .iter()
            .any(|o| std::mem::discriminant(o) == std::mem::discriminant(&opt))
        {
            bail!("Option is already set");
        }

        self.global_probes_options.push(opt);
        Ok(())
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
    pub(crate) fn add_probe(&mut self, mut probe: Probe) -> Result<()> {
        let key = probe.key();

        let len = probe.hooks_len();
        if len + self.generic_hooks.len() > HOOK_MAX {
            bail!("Hook list is already full");
        }

        // Check if it is already in the probe list.
        if let Some(prev) = self.probes.get_mut(&key) {
            if prev.hooks_len() + len + self.generic_hooks.len() > HOOK_MAX {
                bail!("Hook list is already full");
            }

            prev.merge(&mut probe)?;
            return Ok(());
        }

        // If not, insert it.
        self.check_probe_max()?;
        self.probes.insert(key, probe);

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
        self.probes.iter().for_each(|(_, p)| {
            if max < p.hooks_len() {
                max = p.hooks_len();
            }
        });

        if self.generic_hooks.len() + max >= HOOK_MAX {
            bail!("Hook list is already full");
        }

        self.generic_hooks.push(hook);
        Ok(())
    }

    /// Attach all probes.
    pub(crate) fn attach(&mut self) -> Result<()> {
        // Prepare all hooks:
        // - Reuse global maps.
        // - Set global options.
        self.generic_hooks
            .iter_mut()
            .for_each(|h| h.maps.extend(self.maps.clone()));
        self.probes.iter_mut().try_for_each(|(_, p)| {
            p.hooks
                .iter_mut()
                .for_each(|h| h.maps.extend(self.maps.clone()));
            self.global_probes_options
                .iter()
                .try_for_each(|o| p.set_option(o.clone()))
        })?;

        // Handle generic probes.
        self.builders.extend(Self::attach_probes(
            &mut self
                .probes
                .values_mut()
                .filter(|p| p.hooks_len() == 0)
                .collect::<Vec<&mut Probe>>(),
            &self.generic_hooks,
            &self.filters,
            self.maps.clone(),
            #[cfg(not(test))]
            &mut self.config_map,
        )?);

        // Then targeted ones.
        self.probes
            .iter_mut()
            .filter(|(_, p)| p.hooks_len() > 0)
            .try_for_each(|(_, p)| -> Result<()> {
                let mut hooks = p.hooks.clone();
                if p.supports_generic_hooks() {
                    hooks.extend(self.generic_hooks.clone());
                }

                self.builders.extend(Self::attach_probes(
                    &mut [p],
                    &hooks,
                    &self.filters,
                    self.maps.clone(),
                    #[cfg(not(test))]
                    &mut self.config_map,
                )?);
                Ok(())
            })?;

        Ok(())
    }

    // Behind the scene logic to attach a set of probes using a common context
    // (hooks, filters, etc).
    //
    // Returns a reference to the probe builders used, so the attached BPF
    // programs don't go away.
    fn attach_probes(
        probes: &mut [&mut Probe],
        hooks: &[Hook],
        filters: &[Filter],
        maps: HashMap<String, i32>,
        #[cfg(not(test))] config_map: &mut libbpf_rs::Map,
    ) -> Result<Vec<Box<dyn ProbeBuilder>>> {
        let mut builders: HashMap<usize, Box<dyn ProbeBuilder>> = HashMap::new();
        let map_fds: Vec<(String, i32)> = maps.into_iter().collect();

        probes.iter_mut().try_for_each(|probe| {
            // Make a new builder if none if found for the current type. Builder
            // are shared for all probes of the same type within this set.
            match builders.contains_key(&probe.type_key()) {
                false => {
                    let mut builder: Box<dyn ProbeBuilder> = match probe.r#type() {
                        ProbeType::Kprobe(_) => Box::new(kprobe::KprobeBuilder::new()),
                        ProbeType::Kretprobe(_) => Box::new(kretprobe::KretprobeBuilder::new()),
                        ProbeType::RawTracepoint(_) => {
                            Box::new(raw_tracepoint::RawTracepointBuilder::new())
                        }
                        ProbeType::Usdt(_) => Box::new(usdt::UsdtBuilder::new()),
                    };

                    // Initialize the probe builder, only once for all targets.
                    builder.init(map_fds.clone(), hooks.to_vec(), filters.to_owned())?;

                    builders.insert(probe.type_key(), builder);
                }
                true => (),
            }
            // Unwrap as we just made sure the probe builder would be available.
            let builder = builders.get_mut(&probe.type_key()).unwrap();

            // First load the probe configuration.
            #[cfg(not(test))]
            let options = probe.options();
            #[cfg(not(test))]
            match probe.type_mut() {
                ProbeType::Kprobe(ref mut p)
                | ProbeType::Kretprobe(ref mut p)
                | ProbeType::RawTracepoint(ref mut p) => {
                    let addr = p.symbol.addr()?.to_ne_bytes();
                    let config = p.gen_config(&options)?;
                    let config = unsafe { plain::as_bytes(&config) };
                    config_map.update(&addr, config, libbpf_rs::MapFlags::ANY)?;
                }
                _ => (),
            }

            // Finally attach a probe to the target.
            debug!("Attaching probe to {}", probe);
            builder.attach(probe)
        })?;

        // All probes loaded, issue an info log.
        info!("{} probe(s) loaded", probes.len());

        Ok(builders.drain().map(|(_, v)| v).collect())
    }

    fn check_probe_max(&self) -> Result<()> {
        if self.probes.len() >= PROBE_MAX {
            bail!(
                "Can't register probe, reached maximum capacity ({})",
                PROBE_MAX
            );
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

        let mut probe = kprobe!("kfree_skb_reason");
        probe.add_hook(Hook::from(HOOK)).unwrap();
        assert!(mgr.add_probe(kprobe!("kfree_skb_reason")).is_ok());
        assert!(mgr.add_probe(probe).is_ok());
        assert!(mgr.add_probe(kprobe!("kfree_skb_reason")).is_ok());

        assert!(mgr.add_probe(raw_tp!("skb:kfree_skb")).is_ok());
        let mut probe = raw_tp!("skb:kfree_skb");
        probe.add_hook(Hook::from(HOOK)).unwrap();
        probe.add_hook(Hook::from(HOOK)).unwrap();
        assert!(mgr.add_probe(probe).is_ok());

        for _ in 0..HOOK_MAX - 4 {
            assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_ok());
        }

        // We should hit the hook limit here.
        assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_err());

        let mut probe = kprobe!("kfree_skb_reason");
        probe.add_hook(Hook::from(HOOK)).unwrap();
        assert!(mgr.add_probe(probe).is_ok());

        // We should hit the hook limit here as well.
        let mut probe = kprobe!("kfree_skb_reason");
        probe.add_hook(Hook::from(HOOK)).unwrap();
        assert!(mgr.add_probe(probe).is_err());

        let mut probe = raw_tp!("skb:kfree_skb");
        probe.add_hook(Hook::from(HOOK)).unwrap();
        assert!(mgr.add_probe(probe).is_err());
    }

    #[test]
    fn reuse_map() {
        let mut mgr = ProbeManager::new().unwrap();

        assert!(mgr.reuse_map("config", 0).is_ok());
        assert!(mgr.reuse_map("event", 0).is_ok());
        assert!(mgr.reuse_map("event", 0).is_err());
    }
}
