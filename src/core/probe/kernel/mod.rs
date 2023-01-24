//! # Kernel probes
//!
//! Module providing an API to attach probes in the Linux kernel, e.g. using
//! kprobes and raw tracepoints. The need to attach a probe in the kernel can
//! come from various sources (different collectors, the user, etc) and as such
//! some kind of synchronization and common logic is required; which is provided
//! here.
//!
//! Additional BPF function (defined outside this module) can be registered and
//! dynamically attached to the probes. These are refered as hooks. We support
//! registering hooks in different ways:
//!
//! 1. Hooks can be attached to all probes, using the generic register_hook()
//!    API. Those hooks will be attached to all running probes in the kernel.
//!    Note: for the hook to actually run, at least one probe must be added,
//!    with the add_probe() API.
//!
//! 2. Targeted hooks, attached to a specific probe, using the
//!    register_hook_to() API.

// Re-export kernel.rs
#[allow(clippy::module_inception)]
pub(crate) mod kernel;
pub(crate) use kernel::*;

pub(crate) mod config;
mod inspect;
pub(in crate::core::probe) mod kprobe;
pub(in crate::core::probe) mod raw_tracepoint;
