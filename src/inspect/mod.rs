//! # Inspect
//!
//! Provides a command for inspecting the current machine; to ease later
//! collection.

// Re-export inspect.rs
#[allow(clippy::module_inception)]
pub(crate) mod inspect;
pub(crate) use inspect::*;
