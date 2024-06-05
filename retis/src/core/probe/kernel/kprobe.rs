//! # Kprobe
//!
//! Module to handle attaching programs to kernel probes. The module is split
//! in two parts, the Rust code (here) and the eBPF one (bpf/kprobe.bpf.c and
//! its auto-generated part in bpf/.out/).

use std::os::fd::{AsFd, AsRawFd, RawFd};

use anyhow::{anyhow, bail, Result};
use libbpf_rs::skel::SkelBuilder;

use crate::core::{filters::Filter, probe::builder::*, probe::*};

mod kprobe_bpf {
    include!("bpf/.out/kprobe.skel.rs");
}
use kprobe_bpf::KprobeSkelBuilder;

#[derive(Default)]
pub(crate) struct KprobeBuilder {
    links: Vec<libbpf_rs::Link>,
    obj: Option<libbpf_rs::Object>,
}

impl ProbeBuilder for KprobeBuilder {
    fn new() -> KprobeBuilder {
        KprobeBuilder::default()
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: Vec<Hook>,
        filters: Vec<Filter>,
    ) -> Result<()> {
        if self.obj.is_some() {
            bail!("Kprobe builder already initialized");
        }

        let mut skel = KprobeSkelBuilder::default().open()?;
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
            .prog("probe_kprobe")
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
            _ => bail!("Kprobe builder is uninitialized"),
        };
        let probe = match probe.r#type() {
            ProbeType::Kprobe(probe) => probe,
            _ => bail!("Wrong probe type {}", probe),
        };

        self.links.push(
            obj.prog_mut("probe_kprobe")
                .ok_or_else(|| anyhow!("Couldn't get program"))?
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
            "kprobe/probe",
            libbpf_rs::ProgramType::Kprobe,
            Some(fixup_filter_load_fn),
        );

        let mut builder = KprobeBuilder::new();

        assert!(builder.init(Vec::new(), Vec::new(), Vec::new()).is_ok());
        assert!(builder
            .attach(&Probe::kprobe(Symbol::from_name("kfree_skb_reason").unwrap()).unwrap())
            .is_ok());
        assert!(builder
            .attach(&Probe::kprobe(Symbol::from_name("consume_skb").unwrap()).unwrap())
            .is_ok());
    }
}
