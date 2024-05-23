#![allow(dead_code)] // FIXME
#![cfg_attr(test, allow(unused_imports))]
use std::{
    cmp,
    collections::{HashMap, HashSet},
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

use super::{common::*, kernel::config::init_config_map};
use crate::core::{
    filters::{self, fixup_filter_load_fn, register_filter_handler, Filter},
    kernel::Symbol,
    probe::user::UsdtProbe,
    user::proc::Process,
};

// Keep in sync with their BPF counterparts in bpf/include/common.h
pub(crate) const PROBE_MAX: usize = 1024;
pub(super) const HOOK_MAX: usize = 10;

/// ProbeManager is the main object providing an API for consumers to register
/// probes, hooks, maps, etc. It has two main states: builder and runtime.
///
/// The builder state is used to register probes, hooks, maps, etc for *later*
/// use. The runtime state represents a probe manager handling probes already
/// installed.
///
/// When transitioning from the builder to the runtime state all registered
/// probes are installed. The ProbeManager can only perform the builder ->
/// runtime transition, and can only do so once.
///
/// A third state, None, is representing an empty ProbeManager. This helps its
/// use within other data structures.
#[derive(Default)]
pub(crate) enum ProbeManager {
    #[default]
    None,
    Builder(ProbeBuilderManager),
    Runtime(ProbeRuntimeManager),
}

impl ProbeManager {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self::Builder(ProbeBuilderManager::new()?))
    }

    fn err_state(&self) -> anyhow::Error {
        match self {
            Self::None => anyhow!("Wrong probe manager state: none"),
            Self::Builder(_) => anyhow!("Wrong probe manager state: builder"),
            Self::Runtime(_) => anyhow!("Wrong probe manager state: runtime"),
        }
    }

    pub(crate) fn builder(&self) -> Result<&ProbeBuilderManager> {
        match self {
            Self::Builder(builder) => Ok(builder),
            _ => Err(self.err_state()),
        }
    }

    pub(crate) fn builder_mut(&mut self) -> Result<&mut ProbeBuilderManager> {
        match self {
            Self::Builder(builder) => Ok(builder),
            _ => Err(self.err_state()),
        }
    }

    pub(crate) fn runtime(&self) -> Result<&ProbeRuntimeManager> {
        match self {
            Self::Runtime(runtime) => Ok(runtime),
            _ => Err(self.err_state()),
        }
    }

    pub(crate) fn runtime_mut(&mut self) -> Result<&mut ProbeRuntimeManager> {
        match self {
            Self::Runtime(runtime) => Ok(runtime),
            _ => Err(self.err_state()),
        }
    }

    /// Transition the ProbeManager from the builder state into the runtime one.
    /// This installs all registered probes.
    pub(crate) fn into_runtime(self) -> Result<Self> {
        let mut builder = match self {
            Self::Builder(builder) => builder,
            _ => bail!("Probe manager is already at runtime state"),
        };

        // Prepare all hooks:
        // - Reuse global maps.
        // - Set global options.
        builder
            .generic_hooks
            .iter_mut()
            .for_each(|h| h.maps.extend(builder.maps.clone()));
        builder.probes.values_mut().try_for_each(|p| {
            builder
                .maps
                .iter()
                .try_for_each(|(name, fd)| p.reuse_map(name, *fd))?;
            builder
                .global_probes_options
                .iter()
                .try_for_each(|o| p.set_option(o.clone()))
        })?;

        // Set up filters and their handlers.
        for filter in builder.filters.iter() {
            match filter {
                Filter::Packet(magic, _) => {
                    filters::register_filter(*magic as u32, filter)?;
                }
                #[allow(unused_variables)]
                Filter::Meta(ops) =>
                {
                    #[cfg(not(test))]
                    for (p, op) in ops.0.iter().enumerate() {
                        let pos = u32::try_from(p)?.to_ne_bytes();
                        builder.meta_map.update(
                            &pos,
                            unsafe { plain::as_bytes(op) },
                            libbpf_rs::MapFlags::ANY,
                        )?;
                    }
                }
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

        // Initiliaze the manager runtime.
        #[cfg_attr(test, allow(unused_mut))]
        let mut runtime = ProbeRuntimeManager {
            #[cfg(not(test))]
            config_map: builder.config_map,
            #[cfg(not(test))]
            counters_map: builder.counters_map,
            map_fds: builder.maps.into_iter().collect(),
            hooks: builder.generic_hooks.into_iter().collect(),
            generic_builders: HashMap::new(),
            targeted_builders: Vec::new(),
            probes: HashSet::new(),
            filters: builder.filters,
        };

        // Install probes.
        #[cfg(not(test))]
        builder
            .probes
            .values_mut()
            .try_for_each(|p| match p.is_generic() {
                true => runtime.attach_generic_probe(p),
                false => runtime.attach_targeted_probe(p),
            })?;

        // All probes loaded, issue an info log.
        info!("{} probe(s) loaded", builder.probes.len());

        #[cfg(not(test))]
        {
            // Set the global config once all probes are installed, to avoid
            // inconsistencies.
            let config = GlobalConfig { enabled: 1 };
            let config = unsafe { plain::as_bytes(&config) };
            builder
                .global_config_map
                .update(&[0], config, libbpf_rs::MapFlags::ANY)?;
        }

        Ok(Self::Runtime(runtime))
    }
}

/// ProbeBuilderManager holds data of the builder state of ProbeManager.
pub(crate) struct ProbeBuilderManager {
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
    /// Common configuration for all probes.
    #[cfg(not(test))]
    global_config_map: libbpf_rs::MapHandle,
    /// Dynamic probes requires a map that provides extra information at runtime. This is that map.
    #[cfg(not(test))]
    config_map: libbpf_rs::MapHandle,
    /// Global map used to pass meta filter actions.
    #[cfg(not(test))]
    meta_map: libbpf_rs::MapHandle,
    /// Global per-probe map used to report counters.
    #[cfg(not(test))]
    counters_map: libbpf_rs::MapHandle,
}

impl ProbeBuilderManager {
    pub(crate) fn new() -> Result<Self> {
        // When testing the kernel object is not modified later to reuse the
        // config map is this map is hidden.
        #[allow(unused_mut)]
        let mut mgr = Self {
            probes: HashMap::new(),
            generic_hooks: Vec::new(),
            filters: Vec::new(),
            global_probes_options: Vec::new(),
            maps: HashMap::new(),
            #[cfg(not(test))]
            global_config_map: init_global_config_map()?,
            #[cfg(not(test))]
            config_map: init_config_map()?,
            #[cfg(not(test))]
            meta_map: filters::meta::filter::init_meta_map()?,
            #[cfg(not(test))]
            counters_map: init_counters_map()?,
        };

        #[cfg(not(test))]
        mgr.maps.insert(
            "global_config_map".to_string(),
            mgr.global_config_map.as_fd().as_raw_fd(),
        );

        #[cfg(not(test))]
        mgr.maps
            .insert("config_map".to_string(), mgr.config_map.as_fd().as_raw_fd());

        #[cfg(not(test))]
        mgr.maps.insert(
            "filter_meta_map".to_string(),
            mgr.meta_map.as_fd().as_raw_fd(),
        );

        #[cfg(not(test))]
        mgr.maps.insert(
            "counters_map".to_string(),
            mgr.counters_map.as_fd().as_raw_fd(),
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

/// ProbeRuntimeManager holds data of the runtime state of ProbeManager.
pub(crate) struct ProbeRuntimeManager {
    /// Dynamic probes requires a map that provides extra information at runtime. This is that map.
    #[cfg(not(test))]
    config_map: libbpf_rs::MapHandle,
    /// Global per-probe map used to report counters.
    #[cfg(not(test))]
    counters_map: libbpf_rs::MapHandle,
    generic_builders: HashMap<usize, Box<dyn ProbeBuilder>>,
    targeted_builders: Vec<Box<dyn ProbeBuilder>>,
    map_fds: Vec<(String, RawFd)>,
    hooks: Vec<Hook>,
    probes: HashSet<String>,
    filters: Vec<Filter>,
}

impl ProbeRuntimeManager {
    /// Internal function installing a probe using a type-specific builder.
    #[cfg(not(test))]
    fn attach_probe(
        builder: &mut Box<dyn ProbeBuilder>,
        config_map: &mut libbpf_rs::MapHandle,
        counters_map: &mut libbpf_rs::MapHandle,
        probe: &mut Probe,
    ) -> Result<()> {
        let (counters_key, counters);
        // First load the probe configuration.
        let options = probe.options();

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

        counters_map.update(
            unsafe { plain::as_bytes(&counters_key) },
            unsafe { plain::as_bytes(&counters) },
            libbpf_rs::MapFlags::ANY,
        )?;

        // Finally attach a probe to the target.
        debug!("Attaching probe to {}", probe);
        builder.attach(probe)
    }

    /// Generate a new builder for the given probe.
    fn gen_builder(probe: &Probe) -> Box<dyn ProbeBuilder> {
        match probe.r#type() {
            ProbeType::Kprobe(_) => Box::new(kprobe::KprobeBuilder::new()),
            ProbeType::Kretprobe(_) => Box::new(kretprobe::KretprobeBuilder::new()),
            ProbeType::RawTracepoint(_) => Box::new(raw_tracepoint::RawTracepointBuilder::new()),
            ProbeType::Usdt(_) => Box::new(usdt::UsdtBuilder::new()),
        }
    }

    /// Populates generic builders.
    fn gen_generic_builders(&mut self) -> Result<()> {
        // Already initialized? Bail out early.
        if !self.generic_builders.is_empty() {
            return Ok(());
        }

        let fake_probes = [
            Probe::kprobe(Symbol::from_name_no_inspect("dummy"))?,
            Probe::kretprobe(Symbol::from_name_no_inspect("dummy"))?,
            Probe::raw_tracepoint(Symbol::from_name_no_inspect("dummy:dummy"))?,
            Probe::usdt(UsdtProbe::dummy())?,
        ];

        let mut builders = HashMap::new();
        fake_probes.iter().try_for_each(|p| -> Result<()> {
            let mut builder = ProbeRuntimeManager::gen_builder(p);

            builder.init(
                self.map_fds.clone(),
                if p.supports_generic_hooks() {
                    self.hooks.clone()
                } else {
                    Vec::new()
                },
                self.filters.clone(),
            )?;

            builders.insert(p.type_key(), builder);
            Ok(())
        })?;

        self.generic_builders = builders;
        Ok(())
    }

    /// Attach a new targeted probe.
    #[cfg(not(test))]
    fn attach_targeted_probe(&mut self, probe: &mut Probe) -> Result<()> {
        if !self.probes.insert(probe.key()) {
            bail!("A probe on {probe} is already attached");
        }

        let mut builder = Self::gen_builder(probe);

        let mut hooks = probe.hooks.clone();
        if probe.supports_generic_hooks() {
            hooks.extend(self.hooks.clone());
        }

        builder.init(self.map_fds.clone(), hooks, self.filters.clone())?;

        Self::attach_probe(
            &mut builder,
            &mut self.config_map,
            &mut self.counters_map,
            probe,
        )?;
        self.targeted_builders.push(builder);
        Ok(())
    }

    /// Attach a new generic probe.
    #[cfg(not(test))]
    pub(crate) fn attach_generic_probe(&mut self, probe: &mut Probe) -> Result<()> {
        if !self.probes.insert(probe.key()) {
            bail!("A probe on {probe} is already attached");
        }

        self.gen_generic_builders()?;

        let builder = self.generic_builders.get_mut(&probe.r#type_key()).unwrap();
        Self::attach_probe(builder, &mut self.config_map, &mut self.counters_map, probe)
    }

    /// Get the list of all currently attached probes.
    pub(crate) fn attached_probes(&self) -> Vec<String> {
        self.probes.clone().into_iter().collect()
    }

    /// Detach all probes.
    pub(crate) fn detach(&mut self) -> Result<()> {
        self.generic_builders
            .values_mut()
            .try_for_each(|builder| builder.detach())?;
        self.targeted_builders
            .iter_mut()
            .try_for_each(|builder| builder.detach())
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
        let mut mgr = ProbeBuilderManager::new().unwrap();

        assert!(mgr.register_probe(kprobe!("kfree_skb_reason")).is_ok());
        assert!(mgr.register_probe(kprobe!("consume_skb")).is_ok());
        assert!(mgr.register_probe(kprobe!("consume_skb")).is_ok());

        assert!(mgr.register_probe(raw_tp!("skb:kfree_skb")).is_ok());
        assert!(mgr.register_probe(raw_tp!("skb:kfree_skb")).is_ok());
    }

    #[test]
    fn register_hooks() {
        let mut mgr = ProbeBuilderManager::new().unwrap();

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
        let mut mgr = ProbeBuilderManager::new().unwrap();

        assert!(mgr.reuse_map("config", 0).is_ok());
        assert!(mgr.reuse_map("event", 0).is_ok());
        assert!(mgr.reuse_map("event", 0).is_err());
    }
}
