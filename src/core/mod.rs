//! # Core
//!
//! Core module, providing tools and common logic that can be used by any module
//! within the tool.

pub(crate) mod bpf_sys;
pub(crate) mod filters;
pub(crate) mod helpers;
pub(crate) mod inspect;
pub(crate) mod kernel;
pub(crate) mod logger;
pub(crate) mod probe;
pub(crate) mod signals;
pub(crate) mod tracking;
pub(crate) mod user;
pub(crate) mod workaround;
