//! # Skb drop module
//!
//! Provides support for retrieving drop reasons from skbs.

// Re-export skb_drop.rs
#[allow(clippy::module_inception)]
pub(crate) mod skb_drop;
pub(crate) use skb_drop::*;

pub(crate) mod bpf;
pub(crate) use bpf::SkbDropEventFactory;

mod skb_drop_hook {
    include!("bpf/.out/skb_drop_hook.rs");
}
