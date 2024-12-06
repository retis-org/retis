//! # RawTracepoint
//!
//! Module to handle attaching programs to kernel raw tracepoints. We use raw
//! tracepoints over tracepoints to access their arguments. The module is split
//! in two parts, the Rust code (here) and the eBPF one
//! (bpf/raw_tracepoint.bpf.c and its auto-generated part in bpf/.out/).

use std::{
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, RawFd},
};

use anyhow::{anyhow, bail, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

use crate::core::{filters::Filter, probe::builder::*, probe::*};

mod raw_tracepoint_bpf {
    include!("bpf/.out/raw_tracepoint.skel.rs");
}
use raw_tracepoint_bpf::RawTracepointSkelBuilder;

#[derive(Default)]
pub(crate) struct RawTracepointBuilder {
    hooks: Vec<Hook>,
    filters: Vec<Filter>,
    links: Vec<libbpf_rs::Link>,
    map_fds: Vec<(String, RawFd)>,
}

impl ProbeBuilder for RawTracepointBuilder {
    fn new() -> RawTracepointBuilder {
        RawTracepointBuilder::default()
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: Vec<Hook>,
        filters: Vec<Filter>,
    ) -> Result<()> {
        self.map_fds = map_fds;
        self.hooks = hooks;
        self.filters = filters;

        Ok(())
    }

    fn attach(&mut self, probe: &Probe) -> Result<()> {
        let mut open_object = MaybeUninit::uninit();
        let mut skel = RawTracepointSkelBuilder::default().open(&mut open_object)?;

        let probe = match probe.r#type() {
            ProbeType::RawTracepoint(probe) => probe,
            _ => bail!("Wrong probe type {}", probe),
        };

        skel.maps.rodata_data.ksym = probe.symbol.addr()?;
        skel.maps.rodata_data.nargs = probe.symbol.nargs()?;
        skel.maps.rodata_data.nhooks = self.hooks.len() as u32;
        skel.maps.rodata_data.log_level = log::max_level() as u8;

        self.filters.iter().for_each(|f| {
            if let Filter::Meta(m) = f {
                skel.maps.rodata_data.nmeta = m.0.len() as u32
            }
        });

        reuse_map_fds(skel.open_object_mut(), &self.map_fds)?;

        let skel = skel.load()?;
        let prog = skel
            .object()
            .progs_mut()
            .find(|p| p.name() == "probe_raw_tracepoint")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;

        let mut links = replace_hooks(prog.as_fd().as_raw_fd(), &self.hooks)?;
        self.links.append(&mut links);

        self.links
            .push(prog.attach_raw_tracepoint(probe.symbol.attach_name())?);
        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        self.links.drain(..);
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

        let mut builder = RawTracepointBuilder::new();

        // It's for now, the probes below won't do much.
        assert!(builder.init(Vec::new(), Vec::new(), Vec::new()).is_ok());
        assert!(builder
            .attach(&Probe::raw_tracepoint(Symbol::from_name("skb:kfree_skb").unwrap()).unwrap())
            .is_ok());
        assert!(builder
            .attach(&Probe::raw_tracepoint(Symbol::from_name("skb:consume_skb").unwrap()).unwrap())
            .is_ok());
    }
}
