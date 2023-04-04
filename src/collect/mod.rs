//! # Collectors
//!
//! Collectors are modules gathering information, mainly collecting events
//! and/or appropriate data; they are at the core of the tool.
//!
//! Depending on the system capabilities, version, etc. collectors might fail at
//! setting up probes or interfacing with their target. Collectors should try
//! hard to work on various environments though; a few pointers to achieve this:
//! - The mandatory part should be kept minimal.
//! - If a probe point or a feature isn't available and if applicable, it should
//!   try to fallback to other approaches. The result might be a loss of
//!   information, which is better than failing. A warning can be displayed in
//!   such cases.
//!   e.g. attaching to kfree_skb_reason in the Linux kernel is better than
//!   attaching to kfree_skb, as the drop reason is otherwise lost, but it is
//!   acceptable as a fallback (mainly for older kernels).

// Re-export collector.rs
#[allow(clippy::module_inception)]
pub(crate) mod collector;
pub(crate) use collector::*;

pub(crate) mod cli;
mod output;
