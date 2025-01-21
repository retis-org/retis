//! # ProbeBuilder
//!
//! ProbeBuilder defines the ProbeBuider trait and some useful utility functions
//!
use std::{
    collections::HashSet,
    ffi::OsStr,
    os::fd::{BorrowedFd, RawFd},
};

use anyhow::Result;

use crate::core::{filters::Filter, probe::*};

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
    fn init(
        &mut self,
        map_fds: Vec<(String, RawFd)>,
        hooks: HashSet<Hook>,
        filters: Vec<Filter>,
    ) -> Result<()>;
    /// Attach a probe to a given target (function, tracepoint, etc).
    fn attach(&mut self, probe: &Probe) -> Result<()>;
    /// Detach all probes installed by the builder (function,
    /// tracepoint, etc).
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

#[macro_export]
macro_rules! enable_hooks {
    ($cfg: expr, $hooks: expr) => {{
        use Hook::*;
        $hooks.iter().for_each(|h| match h {
            SkbTracking => $cfg.skb_tracking = 1,
            SkbDrop => $cfg.skb_drop = 1,
            Skb => $cfg.skb = 1,
            Ct => $cfg.ct = 1,
            Nft => $cfg.nft = 1,
        });
        $cfg.len = $hooks.len() as u32;
    }}
}
