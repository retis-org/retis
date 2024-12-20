//! # Skb module
//!
//! Provide support for retrieving data from `struct sk_buff` kernel objects.

// Re-export skb.rs
#[allow(clippy::module_inception)]
pub(crate) mod skb;
pub(crate) use skb::*;

pub(crate) mod bpf;
pub(crate) use bpf::SkbEventFactory;

mod skb_hook {
    include!("bpf/.out/skb_hook.rs");
}
