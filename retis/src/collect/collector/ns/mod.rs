//! # Namespace collector
//!
//! Reports information about namespaces (currently netns only).

// Re-export ns.rs
#[allow(clippy::module_inception)]
pub(crate) mod ns;
pub(crate) use ns::*;

mod netns_hook {
    include!("bpf/.out/netns_hook.rs");
}
