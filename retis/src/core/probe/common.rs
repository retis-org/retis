//! # Common
//!
//! Module providing infrastructure shared by all probes
use anyhow::{bail, Result};

use crate::core::{inspect, probe::PROBE_MAX};

// Please keep in sync with its BPF counterpart in bpf/include/common_defs.h
#[repr(C)]
pub(crate) struct GlobalConfig {
    pub(crate) enabled: u8,
}
unsafe impl plain::Plain for GlobalConfig {}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn init_global_config_map() -> Result<libbpf_rs::MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    Ok(libbpf_rs::MapHandle::create(
        libbpf_rs::MapType::Hash,
        Some("global_config_map"),
        std::mem::size_of::<u8>() as u32,
        std::mem::size_of::<GlobalConfig>() as u32,
        1,
        &opts,
    )?)
}

// Please keep in sync with its BPF counterpart in bpf/include/common_defs.h
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

// Please keep in sync with its BPF counterpart in bpf/include/common_defs.h
/// Contains the counters of the error path.  This is then processed
/// and reported from user-space. */
#[derive(Default)]
#[repr(C)]
pub(crate) struct Counters {
    pub(crate) dropped_events: u64,
}
unsafe impl plain::Plain for Counters {}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn init_counters_map() -> Result<libbpf_rs::MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    Ok(libbpf_rs::MapHandle::create(
        libbpf_rs::MapType::Hash,
        Some("counters_map"),
        std::mem::size_of::<CountersKey>() as u32,
        std::mem::size_of::<Counters>() as u32,
        PROBE_MAX as u32,
        &opts,
    )?)
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn get_thread_size() -> Result<u32> {
    let inspector = inspect::inspector()?;

    let get_stack_addr = |syms: &[&str]| -> Result<u64> {
        let addr: Vec<_> = syms
            .iter()
            .filter_map(|sym| inspector.kernel.get_symbol_addr(sym).ok())
            .collect();

        if addr.len() != 1 {
            bail!(
                "Cannot retrieve init stack address (found {} entries)",
                addr.len()
            );
        }

        Ok(addr[0])
    };

    let start_addr = get_stack_addr(&["__start_init_stack", "__start_init_task"])?;
    let end_addr = get_stack_addr(&["__end_init_stack", "__end_init_task"])?;

    Ok((end_addr - start_addr) as u32)
}
