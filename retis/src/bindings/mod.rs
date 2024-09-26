//! # Bindings
//!
//! Auto-generated and extended code.
#![allow(
    dead_code,
    clippy::all,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]

pub(crate) mod common_uapi;
use common_uapi::{retis_probe_config, retis_probe_offsets};

impl Default for retis_probe_offsets {
    fn default() -> retis_probe_offsets {
        // -1 means the argument isn't available.
        retis_probe_offsets {
            sk_buff: -1,
            skb_drop_reason: -1,
            net_device: -1,
            net: -1,
            nft_pktinfo: -1,
            nft_traceinfo: -1,
        }
    }
}

unsafe impl plain::Plain for retis_probe_config {}
