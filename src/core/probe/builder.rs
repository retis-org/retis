//! # ProbeBuilder
//!
//! ProbeBuilder defines the ProbeBuider trait and some useful utility functions
//!
use anyhow::{anyhow, Result};

use crate::core::probe::*;

/// Trait representing the interface used to create and handle probes. We use a
/// trait here as we're supporting various attach types.
pub(super) trait ProbeBuilder {
    /// Allocate and return a new instance of the probe builder, with default
    /// values.
    fn new() -> Self
    where
        Self: Sized;
    /// Initialize the probe builder before attaching programs to probes. It
    /// takes an option vector of map fds so that maps can be reused and shared
    /// accross builders.
    fn init(&mut self, map_fds: Vec<(String, i32)>, hooks: Vec<Hook>) -> Result<()>;
    /// Attach a probe to a given target (function, tracepoint, etc).
    fn attach(&mut self, probe: &Probe) -> Result<()>;
}

pub(super) fn reuse_map_fds(
    open_obj: &libbpf_rs::OpenObject,
    map_fds: &[(String, i32)],
) -> Result<()> {
    for map in map_fds.iter() {
        open_obj
            .map(map.0.clone())
            .ok_or_else(|| anyhow!("Couldn't get map {}", map.0.clone()))?
            .reuse_fd(map.1)?;
    }
    Ok(())
}

pub(super) fn replace_hooks(fd: i32, hooks: &[Hook]) -> Result<Vec<libbpf_rs::Link>> {
    let mut links = Vec::new();

    for (i, hook) in hooks.iter().enumerate() {
        let target = format!("hook{}", i);

        let mut open_obj =
            libbpf_rs::ObjectBuilder::default().open_memory("hook", hook.bpf_prog)?;

        // We have to explicitly use a Vec below to avoid having an unknown size
        // at build time.
        let map_fds: Vec<(String, i32)> = hook.maps.clone().into_iter().collect();
        reuse_map_fds(&open_obj, &map_fds)?;

        let open_prog = open_obj
            .prog_mut("hook")
            .ok_or_else(|| anyhow!("Couldn't get hook program"))?;

        open_prog.set_prog_type(libbpf_rs::ProgramType::Ext);
        open_prog.set_attach_target(fd, Some(target))?;

        let mut obj = open_obj.load()?;
        links.push(
            obj.prog_mut("hook")
                .ok_or_else(|| anyhow!("Couldn't get hook program"))?
                .attach_trace()?,
        );
    }
    Ok(links)
}
