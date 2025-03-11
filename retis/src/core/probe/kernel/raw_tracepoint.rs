//! # RawTracepoint
//!
//! Module to handle attaching programs to kernel raw tracepoints. We use raw
//! tracepoints over tracepoints to access their arguments. The module is split
//! in two parts, the Rust code (here) and the eBPF one
//! (bpf/raw_tracepoint.bpf.c and its auto-generated part in bpf/.out/).

use std::os::fd::{AsFd, AsRawFd, RawFd};

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
    skels: Vec<SkelStorage<RawTracepointSkel<'a>>>,
    cookie_support: bool,
    probes: Vec<Probe>,
    hooks: Vec<Hook>,
    ctx_hook: Option<Hook>,
    links: Vec<libbpf_rs::Link>,
    map_fds: Vec<(String, RawFd)>,
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
    ) -> Result<()> {
        self.map_fds = map_fds;
        self.hooks = hooks;
        self.ctx_hook = ctx_hook;

        Ok(())
    }

    fn add_probe(&mut self, probe: Probe) -> Result<()> {
        self.probes.push(probe);
        Ok(())
    }

    fn attach(&mut self) -> Result<()> {
        let tmp = std::mem::take(&mut self.probes);
        tmp.iter().try_for_each(|p| self.attach_raw_tracepoint(p))
    }

    fn detach(&mut self) -> Result<()> {
        self.links.drain(..);
        Ok(())
    }
}

impl RawTracepointBuilder<'_> {
    // Checks whether the underlying kernel supports setting/retrieving cookies
    // in raw tracepoints.
    fn cookie_support() -> Result<bool> {
        Ok(inspect::inspector()?
            .kernel
            .btf
            .resolve_types_by_name("bpf_get_attach_cookie_tracing")
            .is_ok())
    }

    fn attach_raw_tracepoint(&mut self, probe: &Probe) -> Result<()> {
        let mut skel = OpenSkelStorage::new::<RawTracepointSkelBuilder>()?;

        let probe = match probe.r#type() {
            ProbeType::RawTracepoint(probe) => probe,
            _ => bail!("Wrong probe type {}", probe),
        };

        let rodata = skel
            .maps
            .rodata_data
            .as_deref_mut()
            .ok_or_else(|| anyhow!("Can't access eBPF rodata: not memory mapped"))?;
        rodata.nargs = probe.symbol.nargs()?;
        rodata.nhooks = self.hooks.len() as u32;
        rodata.log_level = log::max_level() as u8;

        if !self.cookie_support {
            rodata.ksym = probe.symbol.addr()?;
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

        if self.cookie_support {
            let opts = RawTracepointOpts {
                cookie: probe.symbol.addr()?,
                ..Default::default()
            };

            self.links
                .push(prog.attach_raw_tracepoint_with_opts(probe.symbol.attach_name(), opts)?);
        } else {
            self.links
                .push(prog.attach_raw_tracepoint(probe.symbol.attach_name())?);
        }

        self.skels.push(skel);
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
        assert!(builder.init(Vec::new(), Vec::new(), None).is_ok());
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
