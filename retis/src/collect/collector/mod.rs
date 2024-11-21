//! # Module
//!
//! Modules are per-data/target implementations of data retrieval from kernel or
//! userspace events, specific helpers and post-processing logic.

// Re-export module.rs
#[allow(clippy::module_inception)]
pub(crate) mod module;
pub(crate) use module::*;

pub(crate) mod ct;
pub(crate) mod nft;
pub(crate) mod ovs;
pub(crate) mod skb;
pub(crate) mod skb_drop;
pub(crate) mod skb_tracking;
