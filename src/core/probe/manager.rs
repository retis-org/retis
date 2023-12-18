#![allow(dead_code)] // FIXME
#![cfg_attr(test, allow(unused_imports))]
use std::{
    cmp,
    collections::HashMap,
    os::fd::{AsFd, AsRawFd, RawFd},
};

use anyhow::{anyhow, bail, Result};
use log::{debug, info, warn};
use plain::Plain;

use super::common::{Counters, CountersKey};
use super::*;
use super::{
    builder::ProbeBuilder,
    kernel::{kprobe, kretprobe, raw_tracepoint},
    user::usdt,
};

use super::{common::init_counters_map, kernel::config::init_config_map};
use crate::core::{
    filters::{self, fixup_filter_load_fn, register_filter_handler, Filter},
    kernel::Symbol,
    user::proc::Process,
};

// Keep in sync with their BPF counterparts in bpf/include/common.h
pub(crate) const PROBE_MAX: usize = 1024;
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
    maps: HashMap<String, RawFd>,

    /// Dynamic probes requires a map that provides extra information at runtime. This is that map.
    #[cfg(not(test))]
    config_map: libbpf_rs::MapHandle,

    /// Global per-probe map used to report counters.
    #[cfg(not(test))]
    counters_map: libbpf_rs::MapHandle,

    /// Global map used to pass meta filter actions.
    #[cfg(not(test))]
    meta_map: libbpf_rs::MapHandle,

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
            #[cfg(not(test))]
            counters_map: init_counters_map()?,
            #[cfg(not(test))]
            meta_map: filters::meta::filter::init_meta_map()?,
            builders: Vec::new(),
        };

        #[cfg(not(test))]
        mgr.maps
            .insert("config_map".to_string(), mgr.config_map.as_fd().as_raw_fd());

        #[cfg(not(test))]
        mgr.maps.insert(
            "counters_map".to_string(),
            mgr.counters_map.as_fd().as_raw_fd(),
        );

        #[cfg(not(test))]
        mgr.maps.insert(
            "filter_meta_map".to_string(),
            mgr.meta_map.as_fd().as_raw_fd(),
        );

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
    /// mgr.register_probe(Probe::kprobe(symbol).unwrap()).unwrap();
    ///
    /// let symbol = kernel::Symbol::from_name("skb:kfree_skb").unwrap();
    /// mgr.register_probe(Probe::raw_tracepoint(symbol).unwrap()).unwrap();
    /// ```
    pub(crate) fn register_probe(&mut self, mut probe: Probe) -> Result<()> {
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
    pub(crate) fn reuse_map(&mut self, name: &str, fd: RawFd) -> Result<()> {
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
        // Avoid duplicate filter types as any Filter but
        // Filter::Packet variant can be present once for each kind
        // FilterPacketType
        if self.filters.iter().any(|f| {
            if let Filter::Packet(src_magic, _) = &filter {
                matches!(f, Filter::Packet(dst_magic, _) if *src_magic as u32 == *dst_magic as u32)
            } else {
                std::mem::discriminant(f) == std::mem::discriminant(&filter)
            }
        }) {
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
            max = cmp::max(max, p.hooks_len());
        });

        if self.generic_hooks.len() + max >= HOOK_MAX {
            bail!("Hook list is already full");
        }

        self.generic_hooks.push(hook);
        Ok(())
    }

    fn setup_dyn_filters(&self) -> Result<()> {
        for filter in self.filters.iter() {
            if let Filter::Packet(magic, _) = filter {
                filters::register_filter(*magic as u32, filter)?;
            }
        }

        register_filter_handler(
            "kprobe/probe",
            libbpf_rs::ProgramType::Kprobe,
            Some(fixup_filter_load_fn),
        )?;
        register_filter_handler(
            "kretprobe/probe",
            libbpf_rs::ProgramType::Kprobe,
            Some(fixup_filter_load_fn),
        )?;
        register_filter_handler(
            "raw_tracepoint/probe",
            libbpf_rs::ProgramType::RawTracepoint,
            Some(fixup_filter_load_fn),
        )?;

        Ok(())
    }

    fn setup_map_filters(&mut self) -> Result<()> {
        #[cfg(not(test))]
        for filter in self.filters.iter() {
            if let Filter::Meta(ops) = filter {
                for (p, op) in ops.0.iter().enumerate() {
                    let pos = u32::try_from(p)?.to_ne_bytes();
                    self.meta_map.update(
                        &pos,
                        unsafe { plain::as_bytes(op) },
                        libbpf_rs::MapFlags::ANY,
                    )?;
                }
            }
        }

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
            self.maps
                .iter()
                .try_for_each(|(name, fd)| p.reuse_map(name, *fd))?;
            self.global_probes_options
                .iter()
                .try_for_each(|o| p.set_option(o.clone()))
        })?;

        self.setup_dyn_filters()?;
        self.setup_map_filters()?;

        // Handle generic probes.
        self.builders.extend(Self::attach_probes(
            &mut self
                .probes
                .values_mut()
                .filter(|p| p.is_generic())
                .collect::<Vec<&mut Probe>>(),
            &self.generic_hooks,
            &self.filters,
            self.maps.clone(),
            #[cfg(not(test))]
            &self.config_map,
            #[cfg(not(test))]
            &self.counters_map,
        )?);

        // Then targeted ones.
        self.probes
            .iter_mut()
            .filter(|(_, p)| !p.is_generic())
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
                    &self.config_map,
                    #[cfg(not(test))]
                    &self.counters_map,
                )?);
                Ok(())
            })?;

        // All probes loaded, issue an info log.
        info!("{} probe(s) loaded", self.probes.len());

        Ok(())
    }

    /// Detach all probes.
    pub(crate) fn detach(&mut self) -> Result<()> {
        self.builders
            .iter_mut()
            .try_for_each(|builder| builder.detach())
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
        maps: HashMap<String, RawFd>,
        #[cfg(not(test))] config_map: &libbpf_rs::MapHandle,
        #[cfg(not(test))] counters_map: &libbpf_rs::MapHandle,
    ) -> Result<Vec<Box<dyn ProbeBuilder>>> {
        let mut builders: HashMap<usize, Box<dyn ProbeBuilder>> = HashMap::new();
        let map_fds: Vec<(String, RawFd)> = maps.into_iter().collect();

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
                    builder.init(map_fds.clone(), hooks.to_vec(), filters.to_vec())?;

                    builders.insert(probe.type_key(), builder);
                }
                true => (),
            }
            // Unwrap as we just made sure the probe builder would be available.
            let builder = builders.get_mut(&probe.type_key()).unwrap();

            #[cfg(not(test))]
            let (counters_key, counters);
            // First load the probe configuration.
            #[cfg(not(test))]
            let options = probe.options();
            #[cfg(not(test))]
            match probe.type_mut() {
                ProbeType::Kprobe(ref mut kp)
                | ProbeType::Kretprobe(ref mut kp)
                | ProbeType::RawTracepoint(ref mut kp) => {
                    let addr = kp.symbol.addr()?.to_ne_bytes();
                    let config = kp.gen_config(&options)?;
                    let config = unsafe { plain::as_bytes(&config) };
                    config_map.update(&addr, config, libbpf_rs::MapFlags::ANY)?;
                    (counters_key, counters) = kp.gen_counters()?;
                }
                ProbeType::Usdt(ref mut up) => {
                    (counters_key, counters) = up.gen_counters()?;
                }
            }
            #[cfg(not(test))]
            counters_map.update(
                unsafe { plain::as_bytes(&counters_key) },
                unsafe { plain::as_bytes(&counters) },
                libbpf_rs::MapFlags::ANY,
            )?;

            // Finally attach a probe to the target.
            debug!("Attaching probe to {}", probe);
            builder.attach(probe)
        })?;

        Ok(builders.drain().map(|(_, v)| v).collect())
    }

    #[cfg(test)]
    pub(crate) fn report_counters(&self) -> Result<()> {
        Ok(())
    }

    #[cfg(not(test))]
    pub(crate) fn report_counters(&self) -> Result<()> {
        let mut counters_key = CountersKey::default();
        let mut counters = Counters::default();
        let mut total_lost: u64 = 0;
        let mut proc_cache: HashMap<u64, String> = HashMap::new();

        for k in self.counters_map.keys() {
            counters_key
                .copy_from_bytes(&k)
                .or_else(|_| bail!("Cannot retrieve the counters map key"))?;
            if let Some(counters_val) = self.counters_map.lookup(&k, libbpf_rs::MapFlags::ANY)? {
                counters
                    .copy_from_bytes(&counters_val)
                    .or_else(|_| bail!("Cannot retrieve the counters map value"))?;
                if counters.dropped_events == 0 {
                    continue;
                }

                /* kernel symbols */
                if counters_key.pid == 0 {
                    let ksym = Symbol::from_addr(counters_key.sym_addr)?;
                    warn!("lost {} event(s) from {ksym}", counters.dropped_events);
                } else {
                    let usdt_info;

                    if let Some(path) = proc_cache.get(&counters_key.pid) {
                        usdt_info = path.to_string();
                    } else {
                        let proc = Process::from_pid(counters_key.pid as i32)?;
                        let note = proc
                            .get_note_from_symbol(counters_key.sym_addr)?
                            .ok_or_else(|| anyhow!("Failed to get symbol information"))?;
                        usdt_info = format!("{}:{note}", proc.path().display());
                        proc_cache.insert(counters_key.pid, usdt_info.to_string());
                    }

                    warn!("lost {} event(s) from {usdt_info}", counters.dropped_events);
                }

                total_lost = total_lost.saturating_add(counters.dropped_events);
            }
        }

        if total_lost > 0 {
            warn!("total events lost: {total_lost}");
        }

        Ok(())
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
    fn register_probe() {
        let mut mgr = ProbeManager::new().unwrap();

        assert!(mgr.register_probe(kprobe!("kfree_skb_reason")).is_ok());
        assert!(mgr.register_probe(kprobe!("consume_skb")).is_ok());
        assert!(mgr.register_probe(kprobe!("consume_skb")).is_ok());

        assert!(mgr.register_probe(raw_tp!("skb:kfree_skb")).is_ok());
        assert!(mgr.register_probe(raw_tp!("skb:kfree_skb")).is_ok());
    }

    #[test]
    fn register_hooks() {
        let mut mgr = ProbeManager::new().unwrap();

        assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_ok());
        assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_ok());

        let mut probe = kprobe!("kfree_skb_reason");
        probe.add_hook(Hook::from(HOOK)).unwrap();
        assert!(mgr.register_probe(kprobe!("kfree_skb_reason")).is_ok());
        assert!(mgr.register_probe(probe).is_ok());
        assert!(mgr.register_probe(kprobe!("kfree_skb_reason")).is_ok());

        assert!(mgr.register_probe(raw_tp!("skb:kfree_skb")).is_ok());
        let mut probe = raw_tp!("skb:kfree_skb");
        probe.add_hook(Hook::from(HOOK)).unwrap();
        probe.add_hook(Hook::from(HOOK)).unwrap();
        assert!(mgr.register_probe(probe).is_ok());

        for _ in 0..HOOK_MAX - 4 {
            assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_ok());
        }

        // We should hit the hook limit here.
        assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_err());

        let mut probe = kprobe!("kfree_skb_reason");
        probe.add_hook(Hook::from(HOOK)).unwrap();
        assert!(mgr.register_probe(probe).is_ok());

        // We should hit the hook limit here as well.
        let mut probe = kprobe!("kfree_skb_reason");
        probe.add_hook(Hook::from(HOOK)).unwrap();
        assert!(mgr.register_probe(probe).is_err());

        let mut probe = raw_tp!("skb:kfree_skb");
        probe.add_hook(Hook::from(HOOK)).unwrap();
        assert!(mgr.register_probe(probe).is_err());
    }

    #[test]
    fn reuse_map() {
        let mut mgr = ProbeManager::new().unwrap();

        assert!(mgr.reuse_map("config", 0).is_ok());
        assert!(mgr.reuse_map("event", 0).is_ok());
        assert!(mgr.reuse_map("event", 0).is_err());
    }
}
