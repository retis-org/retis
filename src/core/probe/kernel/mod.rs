//! # Kernel probes
//!
//! Module providing an API to attach probes in the Linux kernel, e.g. using
//! kprobes and raw tracepoints. The need to attach a probe in the kernel can
//! come from various sources (different collectors, the user, etc) and as such
//! some kind of synchronization and common logic is required; which is provided
//! here.
//!
//! Additional BPF function (defined outside this module) can be registered and
//! dynamically attached to the probes. These are refered as hooks. We support
//! registering hooks in different ways:
//!
//! 1. Hooks can be attached to all probes, using the generic register_hook()
//!    API. Those hooks will be attached to all running probes in the kernel.
//!    Note: for the hook to actually run, at least one probe must be added,
//!    with the add_probe() API.
//!
//! 2. Targeted hooks, attached to a specific probe, using the
//!    register_hook_to() API.

#![allow(dead_code)] // FIXME

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use btf_rs::{Btf, Type};
use log::info;

use crate::core::kernel_symbols;

mod kprobe;
mod raw_tracepoint;

/// Probes types supported by this crate.
#[allow(dead_code)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum ProbeType {
    Kprobe,
    RawTracepoint,
    Max,
}

/// Main object representing the kernel probes and providing an API for
/// consumers to register probes, hooks, maps, etc.
pub(crate) struct Kernel {
    /// Probes sets, one per probe type. Used to keep track of all non-specific
    /// probes.
    probes: [ProbeSet; ProbeType::Max as usize],
    /// List of targeted probes, aka. probes running a specific set of hooks.
    /// Targeted probes only have one target to keep things reasonable.
    targeted_probes: Vec<ProbeSet>,
    maps: HashMap<String, i32>,
    hooks: Vec<&'static [u8]>,
    btf: Btf,
}

// Keep in sync with its BPF counterpart in bpf/include/common.h
const HOOK_MAX: usize = 10;

struct ProbeSet {
    r#type: ProbeType,
    builder: Box<dyn ProbeBuilder>,
    targets: HashMap<String, TargetDesc>,
    hooks: Vec<&'static [u8]>,
}

#[derive(Default)]
struct TargetDesc {
    ksym: u64,
    nargs: u32,
}

impl ProbeSet {
    fn new(r#type: ProbeType, builder: Box<dyn ProbeBuilder>) -> ProbeSet {
        ProbeSet {
            r#type,
            builder,
            targets: HashMap::new(),
            hooks: Vec::new(),
        }
    }
}

impl Kernel {
    pub(crate) fn new() -> Result<Kernel> {
        Self::new_from_btf_file("/sys/kernel/btf/vmlinux")
    }

    fn new_from_btf_file(btf_file: &str) -> Result<Kernel> {
        // Keep synced with the order of ProbeType!
        let probes: [ProbeSet; ProbeType::Max as usize] = [
            ProbeSet::new(ProbeType::Kprobe, Box::new(kprobe::KprobeBuilder::new())),
            ProbeSet::new(
                ProbeType::RawTracepoint,
                Box::new(raw_tracepoint::RawTracepointBuilder::new()),
            ),
        ];

        Ok(Kernel {
            probes,
            targeted_probes: Vec::new(),
            maps: HashMap::new(),
            hooks: Vec::new(),
            btf: Btf::from_file(btf_file)?,
        })
    }

    /// Request to attach a probe of type r#type to a target identifier.
    ///
    /// ```
    /// kernel.add_probe(ProbeType::Kprobe, "kfree_skb_reason").unwrap();
    /// kernel.add_probe(ProbeType::RawTracepoint, "kfree_skb").unwrap();
    /// ```
    pub(crate) fn add_probe(&mut self, r#type: ProbeType, target: &str) -> Result<()> {
        let target = target.to_string();

        // First check if it is already in the generic probe list.
        let set = &mut self.probes[r#type as usize];
        if set.targets.contains_key(&target) {
            return Ok(());
        }

        // Then if it is already in the targeted probe list.
        for set in self.targeted_probes.iter_mut() {
            if r#type == set.r#type && set.targets.get(&target).is_some() {
                return Ok(());
            }
        }

        // Filling the probe description here helps in returning errors early to
        // the caller if a target isn't found or is incompatible.
        let desc = self.inspect_target(&r#type, &target)?;

        // Yes, we do it twice, because of the other mut ref for
        // self.inspect_target.
        let set = &mut self.probes[r#type as usize];
        set.targets.insert(target, desc);

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
    /// kernel.register_hook(hook::DATA)?;
    /// ```
    pub(crate) fn register_hook(&mut self, hook: &'static [u8]) -> Result<()> {
        let mut max: usize = 0;
        for set in self.targeted_probes.iter_mut() {
            if max < set.hooks.len() {
                max = set.hooks.len();
            }
        }
        if self.hooks.len() + max == HOOK_MAX {
            bail!("Hook list is already full");
        }

        self.hooks.push(hook);
        Ok(())
    }

    /// Request a hook to be attached to a specific target.
    ///
    /// ```
    /// mod hook {
    ///     include!("bpf/.out/hook.rs");
    /// }
    ///
    /// [...]
    ///
    /// kernel.register_hook_to(hook::DATA, ProbeType::Kprobe, "kfree_skb_reason")?;
    /// ```
    pub(crate) fn register_hook_to(
        &mut self,
        hook: &'static [u8],
        r#type: ProbeType,
        target: &str,
    ) -> Result<()> {
        let target = target.to_string();

        // First check if the target isn't already registered to the generic
        // probes list. If so, remove it from there.
        let target_set = &mut self.probes[r#type as usize];
        target_set.targets.remove(&target);

        // Now check if we already have a targeted probe for this. If so, append
        // the new hook to it.
        for set in self.targeted_probes.iter_mut() {
            if r#type == set.r#type && set.targets.get(&target).is_some() {
                if self.hooks.len() + set.hooks.len() == HOOK_MAX {
                    bail!("Hook list is already full");
                }
                set.hooks.push(hook);
                return Ok(());
            }
        }

        // New target, let's build a new probe set.
        let mut set = ProbeSet::new(
            r#type,
            match r#type {
                ProbeType::Kprobe => Box::new(kprobe::KprobeBuilder::new()),
                ProbeType::RawTracepoint => Box::new(raw_tracepoint::RawTracepointBuilder::new()),
                ProbeType::Max => bail!("Invalid probe type"),
            },
        );

        let desc = self.inspect_target(&r#type, &target)?;
        set.targets.insert(target.to_string(), desc);

        if self.hooks.len() == HOOK_MAX {
            bail!("Hook list is already full");
        }
        set.hooks.push(hook);

        self.targeted_probes.push(set);
        Ok(())
    }

    /// Attach all probes.
    pub(crate) fn attach(&mut self) -> Result<()> {
        // Take care of generic probes first.
        for set in self.probes.iter_mut() {
            Self::attach_set(set, self.maps.clone(), self.hooks.clone())?;
        }

        // Then take care of targeted probes.
        for set in self.targeted_probes.iter_mut() {
            let hooks = [set.hooks.clone(), self.hooks.clone()].concat();
            Self::attach_set(set, self.maps.clone(), hooks)?;
        }

        Ok(())
    }

    fn attach_set(
        set: &mut ProbeSet,
        maps: HashMap<String, i32>,
        hooks: Vec<&'static [u8]>,
    ) -> Result<()> {
        if set.targets.is_empty() {
            return Ok(());
        }

        // Initialize the probe builder, only once for all targets.
        let map_fds = maps.into_iter().collect();
        set.builder.init(map_fds, hooks)?;

        // Attach a probe to all the targets in the set.
        for (target, desc) in set.targets.iter() {
            info!("Attaching probe to {}", target);
            set.builder.attach(target, desc)?;
        }

        Ok(())
    }

    /// Inspect a target using BTF and fill its description.
    fn inspect_target(&self, r#type: &ProbeType, target: &str) -> Result<TargetDesc> {
        // First look at the symbol address. Some probe types might need to
        // modify the target format.
        let ksym_target = match r#type {
            ProbeType::Kprobe => target.to_string(),
            ProbeType::RawTracepoint => format!("__tracepoint_{}", target),
            ProbeType::Max => bail!("Invalid probe type"),
        };
        let mut desc = TargetDesc {
            ksym: kernel_symbols::get_symbol_addr(ksym_target.as_str())?,
            ..Default::default()
        };

        // Then look at the BTF info and inspect the type. Some probe types
        // might need to change the target format (again).
        let proto = match r#type {
            ProbeType::Kprobe => {
                // Kprobes are using directly the target function definition, no
                // change to make to the target format and the prototype
                // resolution is straightforward: Func -> FuncProto.
                let func = match self.btf.resolve_type_by_name(target)? {
                    Type::Func(func) => func,
                    _ => bail!("{} is not a function", target),
                };

                match self.btf.resolve_chained_type(&func)? {
                    Type::FuncProto(proto) => proto,
                    _ => bail!("Function {} does not have a prototype", target),
                }
            }
            ProbeType::RawTracepoint => {
                // Raw tracepoints need to access a symbol derived from
                // TP_PROTO(), which is named "btf_trace_<func>". The prototype
                // resolution is: Typedef -> Ptr -> FuncProto.
                let target = format!("btf_trace_{}", target);

                let func = match self.btf.resolve_type_by_name(target.as_str())? {
                    Type::Typedef(func) => func,
                    _ => bail!("{} is not a typedef", target),
                };

                let ptr = match self.btf.resolve_chained_type(&func)? {
                    Type::Ptr(ptr) => ptr,
                    _ => bail!("{} typedef does not point to a ptr", target),
                };

                match self.btf.resolve_chained_type(&ptr)? {
                    Type::FuncProto(proto) => proto,
                    _ => bail!("Function {} does not have a prototype", target),
                }
            }
            ProbeType::Max => bail!("Invalid probe type"),
        };

        desc.nargs = proto.parameters.len() as u32;

        // Raw tracepoints have a void* pointing to the data as their first
        // argument, which does not end up in their context. We have to skip it.
        // See include/trace/bpf_probe.h in the __DEFINE_EVENT definition.
        if *r#type == ProbeType::RawTracepoint {
            desc.nargs -= 1;
        }

        Ok(desc)
    }
}

/// Trait representing the interface used to create and handle probes. We use a
/// trait here as we're supporting various attach types.
trait ProbeBuilder {
    /// Allocate and return a new instance of the probe builder, with default
    /// values.
    fn new() -> Self
    where
        Self: Sized;
    /// Initialize the probe builder before attaching programs to probes. It
    /// takes an option vector of map fds so that maps can be reused and shared
    /// accross builders.
    fn init(&mut self, map_fds: Vec<(String, i32)>, hooks: Vec<&'static [u8]>) -> Result<()>;
    /// Attach a probe to a given target (function, tracepoint, etc).
    fn attach(&mut self, target: &str, desc: &TargetDesc) -> Result<()>;
}

fn reuse_map_fds(open_obj: &libbpf_rs::OpenObject, map_fds: &[(String, i32)]) -> Result<()> {
    for map in map_fds.iter() {
        open_obj
            .map(map.0.clone())
            .ok_or_else(|| anyhow!("Couldn't get map {}", map.0.clone()))?
            .reuse_fd(map.1)?;
    }
    Ok(())
}

fn replace_hooks(fd: i32, hooks: &[&[u8]]) -> Result<Vec<libbpf_rs::Link>> {
    let mut links = Vec::new();

    for (i, hook) in hooks.iter().enumerate() {
        let target = format!("hook{}", i);

        let mut open_obj = libbpf_rs::ObjectBuilder::default().open_memory("hook", hook)?;
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

    #[test]
    fn add_probe() {
        let mut kernel = Kernel::new_from_btf_file("test_data/vmlinux").unwrap();

        assert!(kernel
            .add_probe(ProbeType::Kprobe, "kfree_skb_reason")
            .is_ok());
        assert!(kernel.add_probe(ProbeType::Kprobe, "consume_skb").is_ok());
        assert!(kernel.add_probe(ProbeType::Kprobe, "consume_skb").is_ok());

        assert!(kernel
            .add_probe(ProbeType::RawTracepoint, "kfree_skb")
            .is_ok());
        assert!(kernel
            .add_probe(ProbeType::RawTracepoint, "kfree_skb")
            .is_ok());
    }

    #[test]
    fn register_hooks() {
        let mut kernel = Kernel::new_from_btf_file("test_data/vmlinux").unwrap();

        assert!(kernel.register_hook(HOOK).is_ok());
        assert!(kernel.register_hook(HOOK).is_ok());

        assert!(kernel
            .register_hook_to(HOOK, ProbeType::Kprobe, "kfree_skb_reason")
            .is_ok());
        assert!(kernel
            .add_probe(ProbeType::Kprobe, "kfree_skb_reason")
            .is_ok());

        kernel
            .add_probe(ProbeType::RawTracepoint, "kfree_skb")
            .unwrap();
        assert!(kernel
            .register_hook_to(HOOK, ProbeType::RawTracepoint, "kfree_skb")
            .is_ok());
        assert!(kernel
            .register_hook_to(HOOK, ProbeType::RawTracepoint, "kfree_skb")
            .is_ok());

        for _ in 0..HOOK_MAX - 4 {
            assert!(kernel.register_hook(HOOK).is_ok());
        }

        // We should hit the hook limit here.
        assert!(kernel.register_hook(HOOK).is_err());

        assert!(kernel
            .register_hook_to(HOOK, ProbeType::Kprobe, "kfree_skb_reason")
            .is_ok());

        // We should hit the hook limit here as well.
        assert!(kernel
            .register_hook_to(HOOK, ProbeType::Kprobe, "kfree_skb_reason")
            .is_err());
        assert!(kernel
            .register_hook_to(HOOK, ProbeType::RawTracepoint, "kfree_skb")
            .is_err());
    }

    #[test]
    fn reuse_map() {
        let mut kernel = Kernel::new_from_btf_file("test_data/vmlinux").unwrap();

        assert!(kernel.reuse_map("config", 0).is_ok());
        assert!(kernel.reuse_map("event", 0).is_ok());
        assert!(kernel.reuse_map("event", 0).is_err());
    }
}
