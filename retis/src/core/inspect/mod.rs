//! # Inspection helpers
//!
//! Provides support for inspecting the system, kernel, symbols, etc.

// Re-export inspect.rs
#[allow(clippy::module_inception)]
pub(crate) mod inspect;
pub(crate) use inspect::*;

mod btf;
pub(crate) mod check;
mod kernel;
pub(crate) mod kernel_version;
