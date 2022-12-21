//! # Probe
//!
//! Module providing a public API to attach to various types of probes.

pub(crate) mod builder;

pub(crate) mod common;
pub(crate) use common::get_ebpf_debug;

pub(crate) mod kernel;
// Re-export kernel::Kernel.
pub(crate) use kernel::Kernel;

#[allow(clippy::module_inception)]
pub(crate) mod probe;
// Re-export probe.
// There is an external module called "probe" so use self::probe to disambiguate.
pub(crate) use self::probe::*;

pub(crate) mod user;
