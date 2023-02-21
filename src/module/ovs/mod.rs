//! # OvsCollector
//!
//! Probe OpenvSwitch kernel probes and tracepoints (as well as USDT) and
//! understand what openvswitch does with a packet.

#[allow(clippy::module_inception)]
pub(crate) mod ovs;
// Re-export ovs.rs
pub(crate) use ovs::*;

mod bpf;
mod kernel_exec_tp {
    include!("bpf/.out/kernel_exec_tp.rs");
}
mod kernel_upcall_tp {
    include!("bpf/.out/kernel_upcall_tp.rs");
}
mod user_recv_upcall {
    include!("bpf/.out/user_recv_upcall.rs");
}
