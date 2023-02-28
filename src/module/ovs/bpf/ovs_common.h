#ifndef __MODULE_OVS_COMMON__
#define __MODULE_OVS_COMMON__

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
enum trace_ovs_data_type {
	OVS_DP_UPCALL =	0,
    OVS_DP_ACTION = 1,
    OVS_DP_ACTION_OUTPUT = 2,
};

#endif /* __MODULE_OVS_COMMON__ */
