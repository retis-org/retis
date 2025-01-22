//! # Kprobe
//!
//! Module to handle attaching programs to kernel probes. The module is split
//! in two parts, the Rust code (here) and the eBPF one (bpf/kprobe.bpf.c and
//! its auto-generated part in bpf/.out/).

use std::{collections::HashSet, os::fd::RawFd};

use anyhow::{anyhow, bail, Result};
use libbpf_rs::skel::{OpenSkel, Skel};

use crate::{
    core::{filters::Filter, probe::builder::*, probe::*, workaround::*},
    enable_hooks,
};

mod kprobe_bpf {
    include!("bpf/.out/kprobe.skel.rs");
}
use kprobe_bpf::*;

#[derive(Default)]
pub(crate) struct KprobeBuilder<'a> {
    links: Vec<libbpf_rs::Link>,
    skel: Option<SkelStorage<KprobeSkel<'a>>>,
}

impl<'a> ProbeBuilder for KprobeBuilder<'a> {
    fn new() -> KprobeBuilder<'a> {
        KprobeBuilder::default()
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: HashSet<Hook>,
        filters: Vec<Filter>,
    ) -> Result<()> {
        if self.skel.is_some() {
            bail!("Kprobe builder already initialized");
        }

        let mut skel = OpenSkelStorage::new::<KprobeSkelBuilder>()?;

        skel.maps.rodata_data.log_level = log::max_level() as u8;
        enable_hooks!(skel.maps.rodata_data.hooks, hooks);

        filters.iter().for_each(|f| {
            if let Filter::Meta(m) = f {
                skel.maps.rodata_data.nmeta = m.0.len() as u32
            }
        });

        reuse_map_fds(skel.open_object_mut(), &map_fds)?;

        self.skel = Some(SkelStorage::load(skel)?);
        Ok(())
    }

    fn attach(&mut self, probe: &Probe) -> Result<()> {
        let obj = match &mut self.skel {
            Some(skel) => skel.object(),
            _ => bail!("Kprobe builder is uninitialized"),
        };
        let probe = match probe.r#type() {
            ProbeType::Kprobe(probe) => probe,
            _ => bail!("Wrong probe type {}", probe),
        };

        self.links.push(
            obj.progs_mut()
                .find(|p| p.name() == "probe_kprobe")
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
