//! # SkbCollector
//!
//! Provide a generic way to probe kernel functions and tracepoints (having a
//! `struct sk_buff *` as a parameter), to filter skbs, and to track them;
//! allowing to reconstruct their path in the Linux networking stack.

// Re-export skb.rs
#[allow(clippy::module_inception)]
pub(crate) mod skb;
pub(crate) use skb::*;
