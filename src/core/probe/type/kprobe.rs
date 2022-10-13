//! # Kprobe
//!
//! Module to handle attaching programs to kernel probes. The module is split
//! in two parts, the Rust code (here) and the eBPF one (bpf/kprobe.bpf.c and
//! its auto-generated part in bpf/out/).

use anyhow::{anyhow, bail, Result};

use super::*;

// TODO: use 'include!()' here when a new libbpf-cargo 0.13 is out.
#[path = "bpf/.out/kprobe.skel.rs"]
mod kprobe;
use kprobe::KprobeSkelBuilder;

#[derive(Default)]
pub(in crate::core::probe) struct KprobeBuilder {
    obj: Option<libbpf_rs::Object>,
    links: Vec<libbpf_rs::Link>,
}

impl ProbeBuilder for KprobeBuilder {
    fn new() -> KprobeBuilder {
        KprobeBuilder::default()
    }

    fn init(&mut self, map_fds: &Vec<(String, i32)>, hooks: Vec<&'static [u8]>) -> Result<()> {
        if self.obj.is_some() {
            bail!("Kprobe builder already initialized");
        }

        let open_obj = KprobeSkelBuilder::default().open()?.obj;
        reuse_map_fds(&open_obj, map_fds)?;

        let obj = open_obj.load()?;
        let fd = obj
            .prog("probe_kprobe")
            .ok_or_else(|| anyhow!("Couldn't get program"))?
            .fd();
        let mut links = freplace_hooks(fd, &hooks)?;
        self.links.append(&mut links);

        self.obj = Some(obj);
        Ok(())
    }

    fn attach(&mut self, target: &str) -> Result<()> {
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
