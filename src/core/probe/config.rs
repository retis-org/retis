// Keep this file in sync w/ type/bpf/common.h

#![allow(non_camel_case_types)]

use std::mem;

use anyhow::Result;

const PROBES_MAX: u32 = 128;

pub(crate) const PROBE_CAP_SK_BUFF: u64 = 1 << 0;

#[repr(C)]
pub(super) struct probe_config {
    pub(super) capabilities: u64,
    pub(super) skb_offset: i32,
}

unsafe impl plain::Plain for probe_config {}

pub(super) fn init_config_map() -> Result<libbpf_rs::Map> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    Ok(libbpf_rs::Map::create(
        libbpf_rs::MapType::Hash,
        Some("config_map"),
        mem::size_of::<u64>() as u32,
        mem::size_of::<probe_config>() as u32,
        PROBES_MAX,
        &opts,
    )?)
}
