//! # Fexit
//!
//! Module to handle attaching programs to kernel fentry. The module is split
//! in two parts, the Rust code (here) and the eBPF one (bpf/fexit.bpf.c and
//! its auto-generated part in bpf/out/).

use anyhow::{anyhow, Result};

use super::*;

// TODO: use 'include!()' here when a new libbpf-cargo 0.13 is out.
#[path = "bpf/.out/fexit.skel.rs"]
mod fexit;
use fexit::FexitSkelBuilder;

#[derive(Default)]
pub(in crate::core::probe) struct FexitBuilder {
    map_fds: Vec<(String, i32)>,
    links: Vec<libbpf_rs::Link>,
    hooks: Vec<&'static [u8]>,
}

impl ProbeBuilder for FexitBuilder {
    fn new() -> FexitBuilder {
        FexitBuilder::default()
    }

    fn init(&mut self, map_fds: &Vec<(String, i32)>, hooks: Vec<&'static [u8]>) -> Result<()> {
        self.map_fds = map_fds.clone();
        self.hooks = hooks;
        Ok(())
    }

    fn attach(&mut self, target: &str) -> Result<()> {
        let mut skel = FexitSkelBuilder::default().open()?;

        // FIXME.
        skel.rodata().ksym = 0;
        skel.rodata().ret_off = 0;

        let mut open_obj = skel.obj;
        reuse_map_fds(&open_obj, &self.map_fds)?;

        open_obj
            .prog_mut("probe_fexit")
            .ok_or_else(|| anyhow!("Couldn't get program"))?
            .set_attach_target(0, Some(target.to_string()))?;

        let mut obj = open_obj.load()?;
        let prog = obj
            .prog_mut("probe_fexit")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;

        let mut links = freplace_hooks(prog.fd(), &self.hooks)?;
        self.links.append(&mut links);

        self.links.push(prog.attach()?);
        Ok(())
    }
}
