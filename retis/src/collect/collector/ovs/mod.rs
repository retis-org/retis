//! # OvsCollector
//!
//! Probe OpenvSwitch kernel probes and tracepoints (as well as USDT) and
//! understand what openvswitch does with a packet.

#[allow(clippy::module_inception)]
pub(crate) mod ovs;
// Re-export ovs.rs
pub(crate) use ovs::*;

pub(crate) mod bpf;
pub(crate) use bpf::OvsEventFactory;
pub(crate) mod flow_info;

mod hooks {
    pub(super) mod kernel_enqueue {
        include!("bpf/.out/kernel_enqueue_hook.rs");
    }
    pub(super) mod kernel_exec_actions {
        include!("bpf/.out/kernel_exec_actions_hook.rs");
    }
    pub(super) mod kernel_exec_actions_ret {
        include!("bpf/.out/kernel_exec_actions_ret_hook.rs");
    }
    pub(super) mod kernel_exec_tp {
        include!("bpf/.out/kernel_exec_tp_hook.rs");
    }
    pub(super) mod kernel_process_packet {
        include!("bpf/.out/kernel_process_packet_hook.rs");
    }
    pub(super) mod kernel_tbl_lookup {
        include!("bpf/.out/kernel_flow_tbl_lookup_hook.rs");
    }
    pub(super) mod kernel_tbl_lookup_ctx {
        include!("bpf/.out/kernel_flow_tbl_lookup_ctx_hook.rs");
    }
    pub(super) mod kernel_tbl_lookup_ret {
        include!("bpf/.out/kernel_flow_tbl_lookup_ret_hook.rs");
    }
    pub(super) mod kernel_upcall_tp {
        include!("bpf/.out/kernel_upcall_tp_hook.rs");
    }
    pub(super) mod kernel_upcall_ret {
        include!("bpf/.out/kernel_upcall_ret_hook.rs");
    }
    pub(super) mod user_op_exec {
        include!("bpf/.out/user_op_exec_hook.rs");
    }
    pub(super) mod user_op_put {
        include!("bpf/.out/user_op_put_hook.rs");
    }
    pub(super) mod user_recv_upcall {
        include!("bpf/.out/user_recv_upcall_hook.rs");
    }
}
