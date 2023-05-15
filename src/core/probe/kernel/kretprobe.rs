//! # Kretprobe
//!
//! Module to handle attaching programs to kernel kretprobes.
//! in two parts, the Rust code (here) and the eBPF one (bpf/kretprobe.bpf.c and
//! its auto-generated part in bpf/.out/).
//!
//! Since function arguments are not available in kretprobes, we attach a small
//! program into the associated kprobe that safes the context into a map which is
//! then retrieved by the kretprobe program..

use anyhow::{anyhow, bail, Result};

use crate::core::filters::Filter;
use crate::core::probe::builder::*;
use crate::core::probe::*;

mod kretprobe_bpf {
    include!("bpf/.out/kretprobe.skel.rs");
}
use kretprobe_bpf::KretprobeSkelBuilder;

#[derive(Default)]
pub(crate) struct KretprobeBuilder {
    obj: Option<libbpf_rs::Object>,
    links: Vec<libbpf_rs::Link>,
}

impl ProbeBuilder for KretprobeBuilder {
    fn new() -> KretprobeBuilder {
        KretprobeBuilder::default()
    }

    fn init(
        &mut self,
        map_fds: Vec<(String, i32)>,
        hooks: Vec<Hook>,
        filters: Vec<Filter>,
    ) -> Result<()> {
        if self.obj.is_some() {
            bail!("Kretprobe builder already initialized");
        }

        let mut skel = KretprobeSkelBuilder::default();
        skel.obj_builder.debug(get_ebpf_debug());
        let mut skel = skel.open()?;
        skel.rodata().nhooks = hooks.len() as u32;

        let open_obj = skel.obj;
        reuse_map_fds(&open_obj, &map_fds)?;

        let obj = open_obj.load()?;
        let fd = obj
            .prog("probe_kretprobe")
            .ok_or_else(|| anyhow!("Couldn't get program"))?
            .fd();
        replace_filters(fd, &filters)?;
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
            obj.prog_mut("probe_kretprobe")
                .ok_or_else(|| anyhow!("Couldn't get kretprobe program"))?
                .attach_kprobe(true, probe.symbol.attach_name())?,
        );

        // Attach the kprobe
        self.links.push(
            obj.prog_mut("probe_kprobe")
                .ok_or_else(|| anyhow!("Couldn't get kprobe program"))?
                .attach_kprobe(false, probe.symbol.attach_name())?,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::kernel::Symbol;

    #[test]
    #[cfg_attr(not(feature = "test_cap_bpf"), ignore)]
    fn init_and_attach() {
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
