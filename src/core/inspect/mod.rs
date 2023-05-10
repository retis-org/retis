//! # Inspection helpers
//!
//! Provides support for inspecting the system, kernel, symbols, etc.

// Re-export inspect.rs
#[allow(clippy::module_inception)]
pub(crate) mod inspect;
pub(crate) use inspect::*;

mod btf;
mod kernel;
mod kernel_version;
