//! # RawTracepoint
//!
//! Module to handle attaching programs to kernel raw tracepoints. We use raw
//! tracepoints over tracepoints to access their arguments. The module is split
//! in two parts, the Rust code (here) and the eBPF one
//! (bpf/raw_tracepoint.bpf.c and its auto-generated part in bpf/out/).

use anyhow::{anyhow, Result};

use super::*;

// TODO: use 'include!()' here when a new libbpf-cargo 0.13 is out.
#[path = "bpf/.out/raw_tracepoint.skel.rs"]
mod raw_tracepoint;
use raw_tracepoint::RawTracepointSkelBuilder;

#[derive(Default)]
pub(in crate::core::probe) struct RawTracepointBuilder {
    map_fds: Vec<(String, i32)>,
    links: Vec<libbpf_rs::Link>,
    hooks: Vec<&'static [u8]>,
}

impl ProbeBuilder for RawTracepointBuilder {
    fn new() -> RawTracepointBuilder {
        RawTracepointBuilder::default()
    }

    fn init(&mut self, map_fds: &Vec<(String, i32)>, hooks: Vec<&'static [u8]>) -> Result<()> {
        self.map_fds = map_fds.clone();
        self.hooks = hooks;
        Ok(())
    }

    fn attach(&mut self, target: &str) -> Result<()> {
        let mut skel = RawTracepointSkelBuilder::default().open()?;

        // FIXME.
        skel.rodata().ksym = 0;
        skel.rodata().last_arg = 0;

        let open_obj = skel.obj;
        reuse_map_fds(&open_obj, &self.map_fds)?;

        let mut obj = open_obj.load()?;
        let prog = obj
            .prog_mut("probe_raw_tracepoint")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;

        let mut links = freplace_hooks(prog.fd(), &self.hooks)?;
        self.links.append(&mut links);

        self.links.push(prog.attach_raw_tracepoint(target)?);
        Ok(())
    }
}
