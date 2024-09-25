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
use std::ffi::{c_char, CStr};

use anyhow::{anyhow, Result};

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
use nft_uapi::{nft_event, nft_offsets};

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

impl nft_event {
    pub(crate) fn to_string(c_array: &[c_char]) -> Result<String> {
        let _null_pos = c_array
            .iter()
            .position(|&c| c == 0)
            .ok_or_else(|| anyhow!("String is not NULL terminated"))?;

        let cstr = unsafe { CStr::from_ptr(c_array.as_ptr()) };
        Ok(cstr.to_string_lossy().into_owned())
    }

    pub(crate) fn to_string_opt(c_array: &[c_char]) -> Result<Option<String>> {
        let res = Self::to_string(c_array)?;

        if res.is_empty() {
            return Ok(None);
        }

        Ok(Some(res))
    }
}

pub(crate) mod skb_tracking_uapi;
use skb_tracking_uapi::*;

unsafe impl plain::Plain for tracking_config {}
unsafe impl plain::Plain for tracking_info {}

pub(crate) mod tracking_hook_uapi;

pub(crate) mod skb_hook_uapi;
