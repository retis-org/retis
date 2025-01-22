//! # Fentry
//!
//! Module to handle attaching programs to kernel raw tracepoints. We use raw
//! tracepoints over tracepoints to access their arguments. The module is split
//! in two parts, the Rust code (here) and the eBPF one
//! (bpf/fentry.bpf.c and its auto-generated part in bpf/.out/).

use std::{collections::HashSet, mem::MaybeUninit, os::fd::RawFd};

use anyhow::{anyhow, bail, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

use crate::{
    core::{filters::Filter, probe::builder::*, probe::*},
    enable_hooks,
};

mod fentry_bpf {
    include!("bpf/.out/fentry.skel.rs");
}
use fentry_bpf::{types::kernel_probe_type, FentrySkelBuilder};

#[derive(Default)]
pub(crate) struct FentryBuilder {
    hooks: HashSet<Hook>,
    filters: Vec<Filter>,
    links: Vec<libbpf_rs::Link>,
    map_fds: Vec<(String, RawFd)>,
}

impl ProbeBuilder for FentryBuilder {
    fn new() -> FentryBuilder {
        FentryBuilder::default()
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: HashSet<Hook>,
        filters: Vec<Filter>,
    ) -> Result<()> {
        self.map_fds = map_fds;
        self.hooks = hooks;
        self.filters = filters;

        Ok(())
    }

    fn attach(&mut self, probe: &Probe) -> Result<()> {
        let mut open_object = MaybeUninit::uninit();
        let mut skel = FentrySkelBuilder::default().open(&mut open_object)?;

        let (fentry, probe) = match probe.r#type() {
            ProbeType::Fentry(probe) => (true, probe),
            ProbeType::Fexit(probe) => (false, probe),
            _ => bail!("Wrong probe type {}", probe),
        };

        skel.maps.rodata_data.probe_type = if fentry {
            kernel_probe_type::KERNEL_PROBE_FENTRY
        } else {
            kernel_probe_type::KERNEL_PROBE_FEXIT
        };
        skel.maps.rodata_data.ksym = probe.symbol.addr()?;
        skel.maps.rodata_data.nargs = probe.symbol.nargs()?;
        skel.maps.rodata_data.log_level = log::max_level() as u8;
        enable_hooks!(skel.maps.rodata_data.hooks, self.hooks);

        self.filters.iter().for_each(|f| {
            if let Filter::Meta(m) = f {
                skel.maps.rodata_data.nmeta = m.0.len() as u32
            }
        });

        reuse_map_fds(skel.open_object_mut(), &self.map_fds)?;

        let mut prog = skel
            .open_object_mut()
            .progs_mut()
            .find(|p| p.name() == "probe_fentry")
            .ok_or_else(|| anyhow!("Couldn't get open program"))?;
        prog.set_attach_type(if fentry {
            libbpf_rs::ProgramAttachType::TraceFentry
        } else {
            libbpf_rs::ProgramAttachType::TraceFexit
        });
        prog.set_attach_target(0, Some(probe.symbol.attach_name()))?;

        let skel = skel.load()?;
        let prog = skel
            .object()
            .progs_mut()
            .find(|p| p.name() == "probe_fentry")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;

        self.links.push(prog.attach_trace()?);
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
            "fentry/probe",
            libbpf_rs::ProgramType::Fentry,
            Some(fixup_filter_load_fn),
        );

        let mut builder = FentryBuilder::new();

        // It's for now, the probes below won't do much.
        assert!(builder.init(Vec::new(), Vec::new(), Vec::new()).is_ok());
        assert!(builder
            .attach(&Probe::fentry(Symbol::from_name("skb:kfree_skb").unwrap()).unwrap())
            .is_ok());
        assert!(builder
            .attach(&Probe::fentry(Symbol::from_name("skb:consume_skb").unwrap()).unwrap())
            .is_ok());
    }
}
