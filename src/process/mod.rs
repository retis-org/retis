//! # Process
//!
//! Process provides commands and utilities for event processing.

// Re-export collector.rs
#[allow(clippy::module_inception)]
pub(crate) mod process;
pub(crate) use process::*;

pub(crate) mod output;
