//! # bpf_sys
//!
//! Module providing facilities to load non-ELF programs.

#[allow(clippy::module_inception)]
pub(crate) mod bpf_sys;
pub(crate) use bpf_sys::*;
