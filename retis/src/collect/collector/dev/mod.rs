//! # Net device collector
//!
//! Reports information about net devices.

// Re-export dev.rs
#[allow(clippy::module_inception)]
pub(crate) mod dev;
pub(crate) use dev::*;

mod dev_hook {
    include!("bpf/.out/dev_hook.rs");
}
