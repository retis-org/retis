use std::mem;

use anyhow::Result;

use crate::{bindings::common_uapi::*, core::probe::PROBE_MAX};

// When testing this isn't used as the config map is hidden.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn init_config_map() -> Result<libbpf_rs::MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    Ok(libbpf_rs::MapHandle::create(
        libbpf_rs::MapType::Hash,
        Some("config_map"),
        mem::size_of::<u64>() as u32,
        mem::size_of::<retis_probe_config>() as u32,
        PROBE_MAX as u32,
        &opts,
    )?)
}

#[cfg(not(test))]
pub(crate) fn init_stack_map() -> Result<libbpf_rs::MapHandle> {
    const MAX_STACKTRACE_ENTRIES: u32 = 256;
    const PERF_MAX_STACK_DEPTH: usize = 127;

    let opts = libbpf_sys::bpf_map_create_opts {
        sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    // Please keep in sync with its BPF counterpart in
    // core/probe/kernel/bpf/include/common.h
    Ok(libbpf_rs::MapHandle::create(
        libbpf_rs::MapType::StackTrace,
        Some("stack_map"),
        mem::size_of::<u32>() as u32,
        (mem::size_of::<u64>() * PERF_MAX_STACK_DEPTH) as u32,
        MAX_STACKTRACE_ENTRIES,
        &opts,
    )?)
}
