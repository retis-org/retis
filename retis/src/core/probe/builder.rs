//! # ProbeBuilder
//!
//! ProbeBuilder defines the ProbeBuider trait and some useful utility functions
//!
use std::{
    ffi::OsStr,
    os::fd::{BorrowedFd, RawFd},
};

use anyhow::{anyhow, Result};

use crate::core::probe::*;

/// Trait representing the interface used to create and handle probes. We use a
/// trait here as we're supporting various attach types.
pub(super) trait ProbeBuilder {
    /// Allocate and return a new instance of the probe builder, with default
    /// values.
    fn new() -> Result<Self>
    where
        Self: Sized;
    /// Initialize the probe builder before attaching programs to probes. It
    /// takes an option vector of map fds so that maps can be reused and shared
    /// accross builders.
    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: Vec<Hook>,
        ctx_hook: Option<Hook>,
    ) -> Result<()>;
    /// Add a probe to the probe builder.
    fn add_probe(&mut self, probe: Probe) -> Result<()>;
    /// Attach all probes added to the builder.
    fn attach(&mut self) -> Result<()>;
    /// Detach all probes installed by the builder.
    fn detach(&mut self) -> Result<()>;
}

pub(super) fn reuse_map_fds(
    open_obj: &mut libbpf_rs::OpenObject,
    map_fds: &[(String, RawFd)],
) -> Result<()> {
    for map in map_fds.iter() {
        if let Some(mut open_map) = open_obj
            .maps_mut()
            .find(|m| m.name() == <String as AsRef<OsStr>>::as_ref(&map.0))
        {
            // Map fds are always valid (they come from libbpf-rs itself) and
            // the map objects are not destroyed until the object is dropped so
            // the fd remains valid here.
            open_map.reuse_fd(unsafe { BorrowedFd::borrow_raw(map.1) })?;
        } else {
            // This object does not have this particular map.
            continue;
        }
    }
    Ok(())
}

pub(super) fn replace_hook(fd: RawFd, hook: &Hook, target: String) -> Result<libbpf_rs::Link> {
    let mut open_obj = libbpf_rs::ObjectBuilder::default().open_memory(hook.bpf_prog)?;

    // We have to explicitly use a Vec below to avoid having an unknown size
    // at build time.
    let map_fds: Vec<(String, RawFd)> = hook.maps.clone().into_iter().collect();
    reuse_map_fds(&mut open_obj, &map_fds)?;

    let mut open_prog = open_obj
        .progs_mut()
        .find(|p| p.section() == "ext/hook")
        .ok_or_else(|| anyhow!("Couldn't get hook program"))?;

    open_prog.set_prog_type(libbpf_rs::ProgramType::Ext);
    open_prog.set_attach_target(fd, Some(target))?;

    let obj = open_obj.load()?;
    let link = obj
        .progs_mut()
        .find(|p| p.section() == "ext/hook")
        .ok_or_else(|| anyhow!("Couldn't get hook program"))?
        .attach_trace()?;
    Ok(link)
}

pub(super) fn replace_hooks(fd: RawFd, hooks: &[Hook]) -> Result<Vec<libbpf_rs::Link>> {
    let mut links = Vec::new();

    for (i, hook) in hooks.iter().enumerate() {
        let target = format!("hook{i}");
        links.push(replace_hook(fd, hook, target)?);
    }
    Ok(links)
}

pub(super) fn replace_ctx_hook(fd: RawFd, hook: &Hook) -> Result<libbpf_rs::Link> {
    replace_hook(fd, hook, "ctx_hook".to_string())
}
