//! # Kretprobe
//!
//! Module to handle attaching programs to kernel kretprobes.
//! in two parts, the Rust code (here) and the eBPF one (bpf/kretprobe.bpf.c and
//! its auto-generated part in bpf/.out/).
//!
//! Since function arguments are not available in kretprobes, we attach a small
//! program into the associated kprobe that safes the context into a map which is
//! then retrieved by the kretprobe program..

use std::os::fd::{AsFd, AsRawFd, RawFd};

use anyhow::{anyhow, bail, Result};
use libbpf_rs::skel::SkelBuilder;

use crate::core::{filters::Filter, probe::builder::*, probe::*};

mod kretprobe_bpf {
    include!("bpf/.out/kretprobe.skel.rs");
}
use kretprobe_bpf::KretprobeSkelBuilder;

#[derive(Default)]
pub(crate) struct KretprobeBuilder {
    links: Vec<libbpf_rs::Link>,
    obj: Option<libbpf_rs::Object>,
}

impl ProbeBuilder for KretprobeBuilder {
    fn new() -> KretprobeBuilder {
        KretprobeBuilder::default()
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: Vec<Hook>,
        filters: Vec<Filter>,
    ) -> Result<()> {
        if self.obj.is_some() {
            bail!("Kretprobe builder already initialized");
        }

        let mut skel = KretprobeSkelBuilder::default().open()?;
        skel.rodata_mut().nhooks = hooks.len() as u32;
        skel.rodata_mut().log_level = log::max_level() as u8;

        filters.iter().for_each(|f| {
            if let Filter::Meta(m) = f {
                skel.rodata_mut().nmeta = m.0.len() as u32
            }
        });

        let open_obj = skel.obj;
        reuse_map_fds(&open_obj, &map_fds)?;

        let obj = open_obj.load()?;
        let fd = obj
            .prog("probe_kretprobe_kretprobe")
            .ok_or_else(|| anyhow!("Couldn't get program"))?
            .as_fd()
            .as_raw_fd();
        let mut links = replace_hooks(fd, &hooks)?;
        self.links.append(&mut links);

        self.obj = Some(obj);
        Ok(())
    }

    fn attach(&mut self, probe: &Probe) -> Result<()> {
        let obj = match &mut self.obj {
            Some(obj) => obj,
            _ => bail!("Kretprobe builder is uninitialized"),
        };

        let probe = match probe.r#type() {
            ProbeType::Kretprobe(probe) => probe,
            _ => bail!("Wrong probe type {}", probe),
        };

        // Attach the kretprobe
        self.links.push(
            obj.prog_mut("probe_kretprobe_kretprobe")
                .ok_or_else(|| anyhow!("Couldn't get kretprobe program"))?
                .attach_kprobe(true, probe.symbol.attach_name())?,
        );

        // Attach the kprobe
        self.links.push(
            obj.prog_mut("probe_kretprobe_kprobe")
                .ok_or_else(|| anyhow!("Couldn't get kprobe program"))?
                .attach_kprobe(false, probe.symbol.attach_name())?,
        );
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
            "kretprobe/probe",
            libbpf_rs::ProgramType::Kprobe,
            Some(fixup_filter_load_fn),
        );

        let mut builder = KretprobeBuilder::new();
        assert!(builder.init(Vec::new(), Vec::new(), Vec::new()).is_ok());
        assert!(builder
            .attach(
                &Probe::kretprobe(Symbol::from_name("tcp_sendmsg").expect("symbol should exist"))
                    .expect("kreprobe creation should succeed")
            )
            .is_ok());
        assert!(builder
            .attach(
                &Probe::kretprobe(
                    Symbol::from_name("skb_send_sock_locked").expect("symbol should exist")
                )
                .expect("kreprobe creation should succeed")
            )
            .is_ok());
    }
}
