//! # Kprobe
//!
//! Module to handle attaching programs to kernel probes. The module is split
//! in two parts, the Rust code (here) and the eBPF one (bpf/kprobe.bpf.c and
//! its auto-generated part in bpf/.out/).

use std::os::fd::{AsFd, AsRawFd, RawFd};

use anyhow::{anyhow, bail, Result};
use libbpf_rs::skel::{OpenSkel, Skel};

use crate::core::{probe::builder::*, probe::*, workaround::*};

mod kprobe_bpf {
    include!("bpf/.out/kprobe.skel.rs");
}
use kprobe_bpf::*;

#[derive(Default)]
pub(crate) struct KprobeBuilder<'a> {
    links: Vec<libbpf_rs::Link>,
    skel: Option<SkelStorage<KprobeSkel<'a>>>,
    kretprobe: bool,
}

impl<'a> ProbeBuilder for KprobeBuilder<'a> {
    fn new() -> Result<KprobeBuilder<'a>> {
        Ok(Default::default())
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: Vec<Hook>,
        ctx_hook: Option<Hook>,
    ) -> Result<()> {
        if self.skel.is_some() {
            bail!("Kprobe builder already initialized");
        }

        let mut skel = OpenSkelStorage::new::<KprobeSkelBuilder>()?;

        let rodata = skel
            .maps
            .rodata_data
            .as_deref_mut()
            .ok_or_else(|| anyhow!("Can't access eBPF rodata: not memory mapped"))?;
        rodata.kretprobe = self.kretprobe;
        rodata.nhooks = hooks.len() as u32;
        rodata.log_level = log::max_level() as u8;

        reuse_map_fds(skel.open_object_mut(), &map_fds)?;

        let skel = SkelStorage::load(skel)?;
        let fd = skel
            .object()
            .progs()
            .find(|p| {
                p.name()
                    == if !self.kretprobe {
                        "probe_kprobe"
                    } else {
                        "probe_kretprobe"
                    }
            })
            .ok_or_else(|| anyhow!("Couldn't get program"))?
            .as_fd()
            .as_raw_fd();

        let mut links = replace_hooks(fd, &hooks)?;
        self.links.append(&mut links);

        if let Some(ctx_hook) = ctx_hook {
            self.links.push(replace_ctx_hook(fd, &ctx_hook)?);
        }

        self.skel = Some(skel);
        Ok(())
    }

    fn attach(&mut self, probe: &Probe) -> Result<()> {
        let obj = match &mut self.skel {
            Some(skel) => skel.object(),
            _ => bail!("Kprobe builder is uninitialized"),
        };

        let symbol = match probe.r#type() {
            ProbeType::Kprobe(probe) if !self.kretprobe => &probe.symbol,
            ProbeType::Kretprobe(probe) if self.kretprobe => &probe.symbol,
            _ => bail!("Wrong probe type {}", probe),
        };

        self.links.push(
            obj.progs_mut()
                .find(|p| p.name() == "probe_kprobe")
                .ok_or_else(|| anyhow!("Couldn't get kprobe program"))?
                .attach_kprobe(false, symbol.attach_name())?,
        );

        if self.kretprobe {
            self.links.push(
                obj.progs_mut()
                    .find(|p| p.name() == "probe_kretprobe")
                    .ok_or_else(|| anyhow!("Couldn't get kretprobe program"))?
                    .attach_kprobe(true, symbol.attach_name())?,
            );
        }

        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        self.links.drain(..);
        Ok(())
    }
}

impl KprobeBuilder<'_> {
    pub(crate) fn kretprobe(mut self) -> Self {
        self.kretprobe = true;
        self
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

        let mut builder = KprobeBuilder::new().unwrap();

        assert!(builder.init(Vec::new(), Vec::new(), None).is_ok());
        assert!(builder
            .attach(&Probe::kprobe(Symbol::from_name("kfree_skb_reason").unwrap()).unwrap())
            .is_ok());
        assert!(builder
            .attach(&Probe::kprobe(Symbol::from_name("consume_skb").unwrap()).unwrap())
            .is_ok());
    }
}
