//! # SkbCollector
//!
//! Provide support for retrieving data from `struct sk_buff` kernel objects.

// Re-export skb.rs
#[allow(clippy::module_inception)]
pub(crate) mod skb;
pub(crate) use skb::*;

mod skb_hook {
    include!("bpf/.out/skb_hook.rs");
}
