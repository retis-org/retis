//! # Process
//!
//! Process provides utilities for commands to perform event processing

// Re-export process.rs
#[allow(clippy::module_inception)]
pub(crate) mod process;
pub(crate) use process::*;
