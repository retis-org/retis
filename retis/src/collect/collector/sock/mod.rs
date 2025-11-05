//! # Socket collector
//!
//! Reports information about sockets.

// Re-export ns.rs
#[allow(clippy::module_inception)]
pub(crate) mod sock;
pub(crate) use sock::*;

mod sock_hook {
    include!("bpf/.out/sock_hook.rs");
}
