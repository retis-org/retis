#include <vmlinux.h>
#include <bpf/usdt.bpf.h>

#include <user_common.h>
#include "ovs_common.h"

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct recv_upcall_event {
	u32 type;
	u32 pkt_size;
	u64 key_size;
	u32 queue_id;
} __attribute__((packed));

static __always_inline u32 queue_id_gen(void *data, u32 len)
{
	int zero = 0;
	struct packet_buffer *buff =
		bpf_map_lookup_elem(&packet_buffers, &zero);
	if (!buff)
		return 0;

	return hash_packet(buff, data, len, 0);
}

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
	recv_event->queue_id = queue_id_gen((void *) ctx->args[2],
					    recv_event->pkt_size);
    return 0;
)

char __license[] SEC("license") = "GPL";
