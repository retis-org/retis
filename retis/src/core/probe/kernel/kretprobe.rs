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
use libbpf_rs::skel::{OpenSkel, Skel};

use crate::core::{probe::builder::*, probe::*, workaround::*};

mod kretprobe_bpf {
    include!("bpf/.out/kretprobe.skel.rs");
}
use kretprobe_bpf::*;

#[derive(Default)]
pub(crate) struct KretprobeBuilder<'a> {
    links: Vec<libbpf_rs::Link>,
    skel: Option<SkelStorage<KretprobeSkel<'a>>>,
}

impl<'a> ProbeBuilder for KretprobeBuilder<'a> {
    fn new() -> KretprobeBuilder<'a> {
        KretprobeBuilder::default()
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: Vec<Hook>,
        ctx_hook: Option<Hook>,
    ) -> Result<()> {
        if self.skel.is_some() {
            bail!("Kretprobe builder already initialized");
        }

        let mut skel = OpenSkelStorage::new::<KretprobeSkelBuilder>()?;

        skel.maps.rodata_data.nhooks = hooks.len() as u32;
        skel.maps.rodata_data.log_level = log::max_level() as u8;

        reuse_map_fds(skel.open_object_mut(), &map_fds)?;

        let skel = SkelStorage::load(skel)?;
        let fd = skel
            .object()
            .progs()
            .find(|p| p.name() == "probe_kretprobe_kretprobe")
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
            _ => bail!("Kretprobe builder is uninitialized"),
        };

        let probe = match probe.r#type() {
            ProbeType::Kretprobe(probe) => probe,
            _ => bail!("Wrong probe type {}", probe),
        };

        // Attach the kretprobe
        self.links.push(
            obj.progs_mut()
                .find(|p| p.name() == "probe_kretprobe_kretprobe")
                .ok_or_else(|| anyhow!("Couldn't get kretprobe program"))?
                .attach_kprobe(true, probe.symbol.attach_name())?,
        );

        // Attach the kprobe
        self.links.push(
            obj.progs_mut()
                .find(|p| p.name() == "probe_kretprobe_kprobe")
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
        assert!(builder.init(Vec::new(), Vec::new(), None).is_ok());
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
