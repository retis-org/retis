//! # Core
//!
//! Core module, providing tools and common logic that can be used by any module
//! within the tool.

pub(crate) mod bpf_sys;
pub(crate) mod events;
pub(crate) mod kernel;
pub(crate) mod probe;
pub(crate) mod user;
pub(crate) mod workaround;
