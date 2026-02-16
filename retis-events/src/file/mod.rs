//! # File
//!
//! Enables storing and retrieving events to/from files.

// Re-export file.rs
#[allow(clippy::module_inception)]
pub mod file;
pub use file::*;

pub mod rotate;
