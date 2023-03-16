//! # Probe
//!
//! Module providing a public API to attach to various types of probes.

mod builder;

pub(crate) mod common;
pub(crate) use common::{get_ebpf_debug, ProbeOption};

pub(crate) mod kernel;

pub(crate) mod manager;
// Re-export manager
pub(crate) use manager::{ProbeManager, PROBE_MAX};

#[allow(clippy::module_inception)]
pub(crate) mod probe;
// Re-export probe.
// There is an external module called "probe" so use self::probe to disambiguate.
pub(crate) use self::probe::*;

pub(crate) mod user;
