//! # User-level probes
//!
//! Module providing an API to attach probes to userspace programs, e.g: using
//! uprobes and USDT.

#[allow(clippy::module_inception)]
pub(crate) mod user;
// Re-export user.rs
#[allow(unused_imports)]
pub(crate) use user::*;

mod proc;
// Re-export user.rs
#[allow(unused_imports)]
pub(crate) use proc::*;
