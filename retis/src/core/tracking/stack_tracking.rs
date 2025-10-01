//! # Stack Tracking
//!
//! Stack tracking extends skb tracking with context capabilities.
//!
//! Functionally, a probe is context-tracked if its processing chain and code path
//! originate from an skb that was initially skb-tracked.
//!
//! When an skb is tracked, a unique stack context is generated, and the entire
//! skb code path is subsequently tracked within that context. This enables the
//! entire skb code path to be tracked, regardless of matching or caching mechanisms,
//! as long as the stack remains the same. Even with deferred processing
//! (e.g., backlog), stack tracking updates and realigns with skb tracking at the
//! point of resumption.
//!
//! The fundamental invariant is that a given context (process or atomic) processes
//! only one skb at a time; a context is exclusively owned by a single skb at
//! any given moment, meaning, different CPUs do not handle different skbs with
//! in the same context.
//!
//! Stack tracking comprises two main components:
//!
//! - The startup component: Determines the stack size for the current system
//!   (specifically for kernel threads and soft interrupts). This information is used
//!   by programs to quickly identify the base address of the current stack and
//!   thus the context of the packet.
//!
//! - The runtime logic: This logic is tied to skb tracking, which serves as its
//!   entry point. It doesn't use separated garbage collection but instead relies on a
//!   self-cleanup mechanism, which can result in stale entries. Stale entries are not
//!   expected to cause further issues since skb tracking remains the primary entry point.

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
