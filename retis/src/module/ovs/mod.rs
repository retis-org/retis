//! # OvsCollector
//!
//! Probe OpenvSwitch kernel probes and tracepoints (as well as USDT) and
//! understand what openvswitch does with a packet.

#[allow(clippy::module_inception)]
pub(crate) mod ovs;
// Re-export ovs.rs
pub(crate) use ovs::*;
pub(crate) mod bpf;

mod hooks {
    pub(super) mod kernel_enqueue {
        include!("bpf/.out/kernel_enqueue.rs");
    }
    pub(super) mod kernel_exec_actions {
        include!("bpf/.out/kernel_exec_actions.rs");
    }
    pub(super) mod kernel_exec_actions_ret {
        include!("bpf/.out/kernel_exec_actions_ret.rs");
    }
    pub(super) mod kernel_exec_tp {
        include!("bpf/.out/kernel_exec_tp.rs");
    }
    pub(super) mod kernel_upcall_tp {
        include!("bpf/.out/kernel_upcall_tp.rs");
    }
    pub(super) mod kernel_upcall_ret {
        include!("bpf/.out/kernel_upcall_ret.rs");
    }
    pub(super) mod user_op_exec {
        include!("bpf/.out/user_op_exec.rs");
    }
    pub(super) mod user_op_put {
        include!("bpf/.out/user_op_put.rs");
    }
    pub(super) mod user_recv_upcall {
        include!("bpf/.out/user_recv_upcall.rs");
    }
}
