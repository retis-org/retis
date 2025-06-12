//! # Stack tracking
//!
//! FIXME: add doc

use std::{
    mem,
    os::fd::{AsFd, AsRawFd},
};

use anyhow::{bail, Result};

use crate::core::probe::manager::ProbeBuilderManager;

pub(crate) fn init_stack_tracking(
    probes: &mut ProbeBuilderManager,
) -> Result<libbpf_rs::MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    // Please keep in sync with its BPF counterpart.
    let stack_tracking_map = libbpf_rs::MapHandle::create(
        libbpf_rs::MapType::LruHash,
        Some("stack_tracking_map"),
        mem::size_of::<u64>() as u32,
        mem::size_of::<u64>() as u32,
        8192,
        &opts,
    )
    .or_else(|e| bail!("Could not create the stack tracking map: {}", e))?;

    probes.reuse_map("stack_tracking_map", stack_tracking_map.as_fd().as_raw_fd())?;

    Ok(stack_tracking_map)
}
