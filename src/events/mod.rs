//! # Events
//!
//! Common event representation and logic.
//!
//! To retrieve BPF events coming from the kernel side, we use a ring buffer.
//! This was preferred over a perf buffer as it presents many advantages leading
//! to better performances. To further improve performances per-CPU ring buffers
//! can be used, this might be an improvement for later. See
//! https://nakryiko.com/posts/bpf-ringbuf/ and
//! tools/testing/selftests/bpf/progs/test_ringbuf_multi.c (in the kernel source
//! tree).

// Re-export events::events.
#[allow(clippy::module_inception)]
pub(crate) mod events;
pub(crate) use events::*;

pub(crate) mod display;
pub(crate) use display::*;

pub(crate) mod file;
pub(crate) mod net;

pub(crate) mod common;
pub(crate) use common::*;
pub(crate) mod ct;
pub(crate) use ct::*;
pub(crate) mod kernel;
pub(crate) use kernel::*;
pub(crate) mod nft;
pub(crate) use nft::*;
pub(crate) mod ovs;
pub(crate) use ovs::*;
pub(crate) mod skb;
pub(crate) use skb::*;
pub(crate) mod skb_drop;
pub(crate) use skb_drop::*;
pub(crate) mod skb_tracking;
pub(crate) use skb_tracking::*;
pub(crate) mod user;
pub(crate) use user::*;
