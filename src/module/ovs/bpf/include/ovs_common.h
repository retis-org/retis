#ifndef __MODULE_OVS_COMMON__
#define __MODULE_OVS_COMMON__

#include <bpf/bpf_core_read.h>

#include "jhash.h"

#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
enum trace_ovs_data_type {
	OVS_DP_UPCALL =	0,
	OVS_DP_UPCALL_QUEUE = 1,
	OVS_DP_UPCALL_RETURN = 2,
	OVS_RECV_UPCALL = 3,
	OVS_OPERATION = 4,
	OVS_DP_ACTION = 5,
	OVS_DP_ACTION_TRACK = 6,
	OVS_DP_ACTION_OUTPUT = 7,
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_INFLIGHT_UPCALLS);
	__type(key, u64);
	__type(value, u32);
} inflight_exec_cmd SEC(".maps");

#define PACKET_HASH_SIZE 64
/* Packet data to be used to for hashing.
 * Stack size is limited in ebpf programs, so we use a per-cpu array to store
 * the data we need to perform the packet hash. */
struct packet_buffer {
	unsigned char data[PACKET_HASH_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct packet_buffer);
} packet_buffers SEC(".maps");


static __always_inline u32 hash_packet(struct packet_buffer *buff,
				        void* pkt_data, u64 size)
{
	__builtin_memset(buff->data, 0, sizeof(buff->data));
	/* Prevent clang from using register mirroring (or any optimization) on
	 * the 'size' variable. */
	barrier_var(size);
	if (size >= PACKET_HASH_SIZE) {
		bpf_probe_read(buff->data, PACKET_HASH_SIZE, pkt_data);
	} else {
		bpf_probe_read(buff->data, size, pkt_data);
	}
	return jhash(buff->data, PACKET_HASH_SIZE, 0);
}

static __always_inline u32 hash_skb(struct packet_buffer *buff,
				     struct sk_buff *skb)
{
	u64 size;
	u32 data_len, len;
	if (!skb) {
		return 0;
	}
	data_len = BPF_CORE_READ(skb, data_len);
	len = BPF_CORE_READ(skb, len);

	if (data_len != 0) {
		size = (len - data_len) & 0xfffffff;
	} else {
		size = len;
	}
	return hash_packet(buff, BPF_CORE_READ(skb, data), size);
}

#endif /* __MODULE_OVS_COMMON__ */
