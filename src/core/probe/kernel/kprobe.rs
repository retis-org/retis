//! # Kprobe
//!
//! Module to handle attaching programs to kernel probes. The module is split
//! in two parts, the Rust code (here) and the eBPF one (bpf/kprobe.bpf.c and
//! its auto-generated part in bpf/.out/).

use anyhow::{anyhow, bail, Result};

use super::{inspect::TargetDesc, *};
use crate::core::probe::get_ebpf_debug;

mod kprobe_bpf {
    include!("bpf/.out/kprobe.skel.rs");
}
use kprobe_bpf::KprobeSkelBuilder;

#[derive(Default)]
pub(super) struct KprobeBuilder {
    obj: Option<libbpf_rs::Object>,
    links: Vec<libbpf_rs::Link>,
}

impl ProbeBuilder for KprobeBuilder {
    fn new() -> KprobeBuilder {
        KprobeBuilder::default()
    }

    fn init(&mut self, map_fds: Vec<(String, i32)>, hooks: Vec<Hook>) -> Result<()> {
        if self.obj.is_some() {
            bail!("Kprobe builder already initialized");
        }

        let mut skel = KprobeSkelBuilder::default();
        skel.obj_builder.debug(get_ebpf_debug());
        let mut skel = skel.open()?;
        skel.rodata().nhooks = hooks.len() as u32;

        let open_obj = skel.obj;
        reuse_map_fds(&open_obj, &map_fds)?;

        let obj = open_obj.load()?;
        let fd = obj
            .prog("probe_kprobe")
            .ok_or_else(|| anyhow!("Couldn't get program"))?
            .fd();
        let mut links = replace_hooks(fd, &hooks)?;
        self.links.append(&mut links);

        self.obj = Some(obj);
        Ok(())
    }

    fn attach(&mut self, target: &str, _: &TargetDesc) -> Result<()> {
        let obj = match &mut self.obj {
            Some(obj) => obj,
            _ => bail!("Kprobe builder is uninitialized"),
        };

        self.links.push(
            obj.prog_mut("probe_kprobe")
                .ok_or_else(|| anyhow!("Couldn't get program"))?
                .attach_kprobe(false, target)?,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(not(feature = "test_cap_bpf"), ignore)]
    fn init_and_attach() {
        let mut builder = KprobeBuilder::new();

        // It's for now, the probes below won't do much.
        let desc = TargetDesc::default();

        assert!(builder.init(Vec::new(), Vec::new()).is_ok());
        assert!(builder.attach("kfree_skb_reason", &desc).is_ok());
        assert!(builder.attach("consume_skb", &desc).is_ok());
        assert!(builder.attach("foobar", &desc).is_err());
    }
}
