//! # OvsCollector
//!
//! Probe OpenvSwitch kernel probes and tracepoints (as well as USDT) and
//! understand what openvswitch does with a packet.

#[allow(clippy::module_inception)]
pub(crate) mod ovs;
// Re-export ovs.rs
pub(crate) use ovs::*;

mod main_hook {
    include!("bpf/.out/main_hook.rs");
}
