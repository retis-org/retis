//! # RawTracepoint
//!
//! Module to handle attaching programs to kernel raw tracepoints. We use raw
//! tracepoints over tracepoints to access their arguments. The module is split
//! in two parts, the Rust code (here) and the eBPF one
//! (bpf/raw_tracepoint.bpf.c and its auto-generated part in bpf/.out/).

use std::{
    collections::HashMap,
    os::fd::{AsFd, AsRawFd, RawFd},
};

use anyhow::{anyhow, bail, Result};
use libbpf_rs::{
    skel::{OpenSkel, Skel},
    RawTracepointOpts,
};

use crate::core::{inspect, probe::builder::*, probe::*, workaround::*};

mod raw_tracepoint_bpf {
    include!("bpf/.out/raw_tracepoint.skel.rs");
}
use raw_tracepoint_bpf::*;

#[derive(Default)]
pub(crate) struct RawTracepointBuilder<'a> {
    skels: HashMap<u32, SkelStorage<RawTracepointSkel<'a>>>,
    legacy_skels: Vec<SkelStorage<RawTracepointSkel<'a>>>,
    cookie_support: bool,
    probes: HashMap<u32, Vec<Probe>>,
    hooks: Vec<Hook>,
    ctx_hook: Option<Hook>,
    links: Vec<libbpf_rs::Link>,
    map_fds: Vec<(String, RawFd)>,
    stack_sz: u32,
}

impl<'a> ProbeBuilder for RawTracepointBuilder<'a> {
    fn new() -> Result<RawTracepointBuilder<'a>> {
        let cookie_support = Self::cookie_support()?;
        log::debug!(
            "Raw tracepoint builder {} cookie support",
            if cookie_support { "with" } else { "without" }
        );

        Ok(Self {
            cookie_support,
            ..Default::default()
        })
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: Vec<Hook>,
        ctx_hook: Option<Hook>,
        stack_sz: u32,
    ) -> Result<()> {
        self.map_fds = map_fds;
        self.hooks = hooks;
        self.ctx_hook = ctx_hook;
        self.stack_sz = stack_sz;

        Ok(())
    }

    fn add_probe(&mut self, probe: Probe) -> Result<()> {
        let nargs = match probe.r#type() {
            ProbeType::RawTracepoint(probe) => probe.symbol.nargs()?,
            _ => bail!("Wrong probe type {}", probe),
        };

        let probes = self.probes.entry(nargs).or_default();
        probes.push(probe);

        Ok(())
    }

    fn attach(&mut self) -> Result<()> {
        let tmp = std::mem::take(&mut self.probes);

        for (nargs, probes) in tmp {
            match self.cookie_support {
                true => self.attach_raw_tracepoints(nargs, &probes)?,
                false => self.attach_raw_tracepoints_no_cookie(&probes)?,
            }
        }

        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        self.links.drain(..);
        Ok(())
    }
}

impl<'a> RawTracepointBuilder<'a> {
    // Checks whether the underlying kernel supports setting/retrieving cookies
    // in raw tracepoints. We both check the availability of the get cookie API
    // as well as the cookie support itself, as the two are part of unrelated
    // commits that could be backported separately.
    fn cookie_support() -> Result<bool> {
        let get_cookie = inspect::inspector()?
            .kernel
            .btf
            .resolve_types_by_name("bpf_get_attach_cookie_tracing")
            .is_ok();
        let raw_tp_cookie = inspect::parse_struct("bpf_raw_tp_link")?
            .iter()
            .any(|field| field == "cookie");

        Ok(get_cookie && raw_tp_cookie)
    }

    fn init_skel(
        &mut self,
        nargs: u32,
        ksym: Option<u64>,
    ) -> Result<SkelStorage<RawTracepointSkel<'a>>> {
        let mut skel = OpenSkelStorage::new::<RawTracepointSkelBuilder>()?;

        let rodata = skel
            .maps
            .rodata_data
            .as_deref_mut()
            .ok_or_else(|| anyhow!("Can't access eBPF rodata: not memory mapped"))?;
        rodata.nargs = nargs;
        rodata.nhooks = self.hooks.len() as u32;
        rodata.log_level = log::max_level() as u8;
        rodata.THREAD_SIZE = self.stack_sz;

        if let Some(ksym) = ksym {
            rodata.ksym = ksym;
        }

        reuse_map_fds(skel.open_object_mut(), &self.map_fds)?;

        let skel = SkelStorage::load(skel)?;
        let prog = skel
            .object()
            .progs_mut()
            .find(|p| p.name() == "probe_raw_tracepoint")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;

        let fd = prog.as_fd().as_raw_fd();
        let mut links = replace_hooks(fd, &self.hooks)?;
        self.links.append(&mut links);

        if let Some(ctx_hook) = &self.ctx_hook {
            self.links.push(replace_ctx_hook(fd, ctx_hook)?);
        }

        Ok(skel)
    }

    fn attach_raw_tracepoints(&mut self, nargs: u32, probes: &[Probe]) -> Result<()> {
        #[allow(clippy::map_entry)] // Fixes double mutable refs.
        if !self.skels.contains_key(&nargs) {
            let new = self.init_skel(nargs, None)?;
            self.skels.insert(nargs, new);
        }

        // Unwrap as we just made sure we have a corresponding skel.
        let skel = self.skels.get_mut(&nargs).unwrap();
        let prog = skel
            .object()
            .progs_mut()
            .find(|p| p.name() == "probe_raw_tracepoint")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;

        for probe in probes {
            let symbol = match probe.r#type() {
                ProbeType::RawTracepoint(probe) => &probe.symbol,
                _ => bail!("Wrong probe type {}", probe),
            };

            let opts = RawTracepointOpts {
                cookie: symbol.addr()?,
                ..Default::default()
            };

            self.links
                .push(prog.attach_raw_tracepoint_with_opts(symbol.attach_name(), opts)?);
        }

        Ok(())
    }

    fn attach_raw_tracepoints_no_cookie(&mut self, probes: &[Probe]) -> Result<()> {
        for probe in probes {
            let symbol = match probe.r#type() {
                ProbeType::RawTracepoint(probe) => &probe.symbol,
                _ => bail!("Wrong probe type {}", probe),
            };

            let skel = self.init_skel(symbol.nargs()?, Some(symbol.addr()?))?;
            let prog = skel
                .object()
                .progs_mut()
                .find(|p| p.name() == "probe_raw_tracepoint")
                .ok_or_else(|| anyhow!("Couldn't get program"))?;

            self.links
                .push(prog.attach_raw_tracepoint(symbol.attach_name())?);
            self.legacy_skels.push(skel);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;

    use crate::core::{
        filters::{fixup_filter_load_fn, register_filter_handler},
        kernel::Symbol,
    };

    #[test]
    #[serial(libbpf)]
    #[cfg_attr(not(feature = "test_cap_bpf"), ignore)]
    fn init_and_attach() {
        let _ = register_filter_handler(
            "raw_tracepoint/probe",
            libbpf_rs::ProgramType::RawTracepoint,
            Some(fixup_filter_load_fn),
        );

        let mut builder = RawTracepointBuilder::new().unwrap();

        // It's for now, the probes below won't do much.
        assert!(builder.init(Vec::new(), Vec::new(), None, 4096).is_ok());
        assert!(builder
            .add_probe(Probe::raw_tracepoint(Symbol::from_name("skb:kfree_skb").unwrap()).unwrap())
            .is_ok());
        assert!(builder
            .add_probe(
                Probe::raw_tracepoint(Symbol::from_name("skb:consume_skb").unwrap()).unwrap()
            )
            .is_ok());
        assert!(builder.attach().is_ok());
    }
}
