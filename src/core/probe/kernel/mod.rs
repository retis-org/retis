//! # Kernel probes
//!
//! Module providing an API to attach probes in the Linux kernel, e.g. using
//! kprobes and raw tracepoints. The need to attach a probe in the kernel can
//! come from various sources (different collectors, the user, etc) and as such
//! some kind of synchronization and common logic is required; which is provided
//! here.

#![allow(dead_code)] // FIXME

use anyhow::Result;

/// Main object representing the kernel probes and providing an API for
/// consumers to register probes, hooks, maps, etc.
pub(crate) struct Kernel {}

impl Kernel {
    pub(crate) fn new() -> Result<Kernel> {
        Ok(Kernel {})
    }

    /// Attach all probes.
    pub(crate) fn attach(&mut self) -> Result<()> {
        Ok(())
    }
}
