//! # Probe
//!
//! Module providing a public API to attach to various types of probes.

pub(crate) mod common;
pub(crate) use common::get_ebpf_debug;

pub(crate) mod kernel;
// Re-export kernel::Kernel.
pub(crate) use kernel::Kernel;

#[allow(clippy::module_inception)]
pub(crate) mod probe;
// Re-export probe.
pub(crate) use probe::*;
