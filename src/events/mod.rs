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

pub(crate) mod bpf;
pub(crate) mod file;

pub(crate) mod ct;
pub(crate) mod nft;
pub(crate) mod ovs;
pub(crate) mod skb;
