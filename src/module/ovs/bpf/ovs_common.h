#ifndef __MODULE_OVS_COMMON__
#define __MODULE_OVS_COMMON__

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
enum trace_ovs_data_type {
	OVS_DP_UPCALL =	0,
	OVS_DP_UPCALL_QUEUE = 1,
	OVS_DP_UPCALL_RETURN = 2,
	OVS_RECV_UPCALL = 3,
	OVS_OPERATION = 4,
	OVS_DP_ACTION = 5,
	OVS_DP_ACTION_OUTPUT = 6,
};

/* Used to keep the context of an upcall operation for its upcall enqueue
 * events. It should uniquely identify a specific upcall. */
/* Please keep in sync with its Rust counterpart in crate::module::ovs::ovs.rs. */
struct upcall_context {
	u64 ts;
	u32 cpu;
} __attribute__((packed));

#define MAX_INFLIGHT_UPCALLS 50
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_INFLIGHT_UPCALLS);
	__type(key, u64);
	__type(value, struct upcall_context);
} inflight_upcalls SEC(".maps");

#endif /* __MODULE_OVS_COMMON__ */
