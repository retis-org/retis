//! # Python support
//!
//! Regroups Python related support for Retis events.

// Re-export python.rs
#[allow(clippy::module_inception)]
pub mod python;
pub use python::*;

#[cfg(feature = "python-shell")]
pub mod shell;
