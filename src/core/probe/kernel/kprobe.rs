//! # Kprobe
//!
//! Module to handle attaching programs to kernel probes. The module is split
//! in two parts, the Rust code (here) and the eBPF one (bpf/kprobe.bpf.c and
//! its auto-generated part in bpf/.out/).

use anyhow::{anyhow, bail, Result};

use super::*;

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

    fn init(&mut self, map_fds: Vec<(String, i32)>, _hooks: Vec<&'static [u8]>) -> Result<()> {
        if self.obj.is_some() {
            bail!("Kprobe builder already initialized");
        }

        let open_obj = KprobeSkelBuilder::default().open()?.obj;
        reuse_map_fds(&open_obj, &map_fds)?;

        let obj = open_obj.load()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(not(feature = "test_cap_bpf"), ignore)]
    fn init_and_attach() {
        let mut builder = KprobeBuilder::new();

        assert!(builder.init(Vec::new(), Vec::new()).is_ok());
        assert!(builder.attach("kfree_skb_reason").is_ok());
        assert!(builder.attach("consume_skb").is_ok());
        assert!(builder.attach("foobar").is_err());
    }
}
