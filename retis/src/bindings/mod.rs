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
use std::mem;

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

pub(crate) mod ct_uapi;
use ct_uapi::ct_event;

unsafe impl plain::Plain for ct_event {}

pub(crate) mod nft_uapi;
use nft_uapi::{nft_event, nft_name_size, nft_offsets};

impl Default for nft_offsets {
    fn default() -> Self {
        Self {
            nft_chain: -1,
            nft_rule: -1,
            nft_verdict: -1,
            nft_type: -1,
        }
    }
}

impl Default for nft_event {
    fn default() -> Self {
        Self {
            table_name: [0; nft_name_size as usize],
            chain_name: [0; nft_name_size as usize],
            verdict_chain_name: [0; nft_name_size as usize],
            verdict: 0,
            t_handle: 0,
            c_handle: 0,
            r_handle: 0,
            policy: 0,
        }
    }
}

pub(crate) mod skb_drop_hook_uapi;

pub(crate) mod skb_tracking_uapi;
use skb_tracking_uapi::*;

unsafe impl plain::Plain for tracking_config {}
unsafe impl plain::Plain for tracking_info {}

pub(crate) mod tracking_hook_uapi;

pub(crate) mod skb_hook_uapi;

pub(crate) mod kernel_enqueue_uapi;
pub(crate) mod kernel_exec_tp_uapi;
pub(crate) mod kernel_upcall_ret_uapi;
pub(crate) mod kernel_upcall_tp_uapi;
use kernel_exec_tp_uapi::exec_ip;

impl Default for exec_ip {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

pub(crate) mod ovs_common_uapi;
pub(crate) mod ovs_operation_uapi;
pub(crate) mod user_recv_upcall_uapi;

pub(crate) mod events_uapi;

use events_uapi::*;

impl Default for common_task_event {
    fn default() -> Self {
        Self {
            pid: 0,
            comm: [0; retis_max_comm as usize],
        }
    }
}

impl Default for retis_log_event {
    fn default() -> Self {
        Self {
            level: 0,
            msg: [0; log_max as usize],
        }
    }
}

unsafe impl plain::Plain for retis_log_event {}
