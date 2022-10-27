//! # Probe
//!
//! Module providing a public API to attach to various types of probes.

pub(crate) mod kernel;
// Re-export kernel::Kernel.
pub(crate) use kernel::Kernel;
