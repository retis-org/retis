//! # Common
//!
//! Module providing infrastructure shared by all probes
use anyhow::Result;
use once_cell::sync::OnceCell;

use crate::core::probe::PROBE_MAX;

static EBPF_DEBUG: OnceCell<bool> = OnceCell::new();

// please keep in sync with its BPF counterpart in bpf/include/common_defs.h
#[derive(Default)]
#[repr(C)]
pub(crate) struct CountersKey {
    /// Symbol address.
    pub(crate) sym_addr: u64,
    /// pid of the process. Zero is used for the
    /// kernel as it is normally reserved the swapper task.
    pub(crate) pid: u64,
}

unsafe impl plain::Plain for CountersKey {}

// please keep in sync with its BPF counterpart in bpf/include/common_defs.h
/// Contains the counters of the error path.  This is then processed
/// and reported from user-space. */
#[derive(Default)]
#[repr(C)]
pub(crate) struct Counters {
    pub(crate) dropped_events: u64,
}

unsafe impl plain::Plain for Counters {}

/// Sets global ebpf debug flag.
///
/// It must only be set once.
/// It will return Ok if it's the first time the it's been set or Err if it was already set.
pub(crate) fn set_ebpf_debug(_debug: bool) -> Result<()> {
    // No need to set it either way in test envs as we're returning true
    // regardless below.
    #[cfg(not(test))]
    EBPF_DEBUG
        .set(_debug)
        .or_else(|_| anyhow::bail!("ebpf_debug was already set"))?;
    Ok(())
}

/// Returns the current value of the global ebpf debug flag.
///
/// If called before [`set_ebpf_debug`] has been called, it will be set to false.
pub(crate) fn get_ebpf_debug() -> bool {
    // Always debug when running tests.
    if cfg!(test) {
        true
    } else {
        *EBPF_DEBUG.get_or_init(|| false)
    }
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn init_counters_map() -> Result<libbpf_rs::Map> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    Ok(libbpf_rs::Map::create(
        libbpf_rs::MapType::Hash,
        Some("counters_map"),
        std::mem::size_of::<CountersKey>() as u32,
        std::mem::size_of::<Counters>() as u32,
        PROBE_MAX as u32,
        &opts,
    )?)
}
