#include <vmlinux.h>
#include <bpf/usdt.bpf.h>

#include <user_common.h>
#include "ovs_common.h"

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct recv_upcall_event {
	u32 type;
	u32 pkt_size;
	u64 key_size;
} __attribute__((packed));

/* Hook for usdt:dpif_recv::recv_upcall. */
DEFINE_USDT_HOOK (
	int res;
	struct recv_upcall_event *recv_event =
		get_event_zsection(event, COLLECTOR_OVS, OVS_RECV_UPCALL ,
				  sizeof(*recv_event));
	if (!recv_event)
		return 0;

	recv_event->type = ctx->args[1];
	recv_event->pkt_size= (u32) ctx->args[3];
	recv_event->key_size = (u64) ctx->args[5];

    return 0;
)

char __license[] SEC("license") = "GPL";
