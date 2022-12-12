//! # User-level probes
//!
//! Module providing an API to attach probes to userspace programs, e.g: using
//! uprobes and USDT.

// Re-export user.rs
#[allow(clippy::module_inception)]
pub(crate) mod user;

#[allow(unused_imports)]
pub(crate) use user::*;
