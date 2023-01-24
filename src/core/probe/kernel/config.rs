use std::mem;

use anyhow::Result;

use crate::core::probe::PROBE_MAX;

/// Per-probe parameter offsets; keep in sync with its BPF counterpart in
/// bpf/include/common.h
#[repr(C)]
pub(super) struct ProbeOffsets {
    pub(super) sk_buff: i8,
    pub(super) skb_drop_reason: i8,
    pub(super) net_device: i8,
    pub(super) net: i8,
}

impl Default for ProbeOffsets {
    fn default() -> ProbeOffsets {
        // -1 means the argument isn't available.
        ProbeOffsets {
            sk_buff: -1,
            skb_drop_reason: -1,
            net_device: -1,
            net: -1,
        }
    }
}

/// Per-probe configuration; keep in sync with its BPF counterpart in
/// bpf/include/common.h
#[derive(Default)]
#[repr(C)]
pub(crate) struct ProbeConfig {
    pub(super) offsets: ProbeOffsets,
}

unsafe impl plain::Plain for ProbeConfig {}

// When testing this isn't used as the config map is hidden.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn init_config_map() -> Result<libbpf_rs::Map> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    Ok(libbpf_rs::Map::create(
        libbpf_rs::MapType::Hash,
        Some("config_map"),
        mem::size_of::<u64>() as u32,
        mem::size_of::<ProbeConfig>() as u32,
        PROBE_MAX as u32,
        &opts,
    )?)
}
