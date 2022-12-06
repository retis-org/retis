//! # RawTracepoint
//!
//! Module to handle attaching programs to kernel raw tracepoints. We use raw
//! tracepoints over tracepoints to access their arguments. The module is split
//! in two parts, the Rust code (here) and the eBPF one
//! (bpf/raw_tracepoint.bpf.c and its auto-generated part in bpf/.out/).

use anyhow::{anyhow, Result};

use super::{inspect::TargetDesc, *};
use crate::core::{kernel::Symbol, probe::get_ebpf_debug};

mod raw_tracepoint_bpf {
    include!("bpf/.out/raw_tracepoint.skel.rs");
}
use raw_tracepoint_bpf::RawTracepointSkelBuilder;

#[derive(Default)]
pub(super) struct RawTracepointBuilder {
    links: Vec<libbpf_rs::Link>,
    map_fds: Vec<(String, i32)>,
    hooks: Vec<Hook>,
}

impl ProbeBuilder for RawTracepointBuilder {
    fn new() -> RawTracepointBuilder {
        RawTracepointBuilder::default()
    }

    fn init(&mut self, map_fds: Vec<(String, i32)>, hooks: Vec<Hook>) -> Result<()> {
        self.map_fds = map_fds;
        self.hooks = hooks;
        Ok(())
    }

    fn attach(&mut self, symbol: &Symbol, desc: &TargetDesc) -> Result<()> {
        let mut skel = RawTracepointSkelBuilder::default();
        skel.obj_builder.debug(get_ebpf_debug());
        let mut skel = skel.open()?;

        skel.rodata().ksym = desc.ksym;
        skel.rodata().nargs = desc.nargs;
        skel.rodata().nhooks = self.hooks.len() as u32;

        let open_obj = skel.obj;
        reuse_map_fds(&open_obj, &self.map_fds)?;

        let mut obj = open_obj.load()?;
        let prog = obj
            .prog_mut("probe_raw_tracepoint")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;

        let mut links = replace_hooks(prog.fd(), &self.hooks)?;
        self.links.append(&mut links);

        self.links
            .push(prog.attach_raw_tracepoint(symbol.func_name())?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(not(feature = "test_cap_bpf"), ignore)]
    fn init_and_attach() {
        let mut builder = RawTracepointBuilder::new();

        // It's for now, the probes below won't do much.
        let desc = TargetDesc::default();

        assert!(builder.init(Vec::new(), Vec::new()).is_ok());
        assert!(builder
            .attach(&Symbol::from_name("skb:kfree_skb").unwrap(), &desc)
            .is_ok());
        assert!(builder
            .attach(&Symbol::from_name("skb:consume_skb").unwrap(), &desc)
            .is_ok());
    }
}
