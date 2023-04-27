#include <vmlinux.h>
#include <bpf/usdt.bpf.h>

#include <user_common.h>
#include <ovs_common.h>
#include <ovs_operation.h>

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct recv_upcall_event {
	u32 type;
	u32 pkt_size;
	u64 key_size;
	u32 queue_id;
	u64 batch_ts;
	u8 batch_idx;
} __attribute__((packed));

static __always_inline u32 queue_id_gen(void *data, u32 len)
{
	int zero = 0;
	struct packet_buffer *buff =
		bpf_map_lookup_elem(&packet_buffers, &zero);
	/* This should always succeed but checks are still needed to keep the
	* verifier happy. */
	if (!buff)
		return 0;

	return hash_packet(buff, data, len);
}

/* Hook for usdt:dpif_recv::recv_upcall. */
DEFINE_USDT_HOOK (
	struct upcall_batch *batch;
	struct recv_upcall_event *recv_event;
	u32 size = (u32) ctx->args[3];
	u32 queue_id = queue_id_gen((void *) ctx->args[2], size);
	bool skip_event = false;

	if (!bpf_map_lookup_elem(&inflight_enqueue, &queue_id)) {
	    /* The upcall enqueue event was missed or filtered. */
	    skip_event = true;
	}
	bpf_map_delete_elem(&inflight_enqueue, &queue_id);


	batch = batch_process_recv(ctx->timestamp, queue_id, skip_event);
	if (!batch)
		return -1;

	if (skip_event)
		return 0;

	recv_event = get_event_zsection(event, COLLECTOR_OVS, OVS_RECV_UPCALL,
					sizeof(*recv_event));
	if (!recv_event)
		return 0;

	recv_event->type = ctx->args[1];
	recv_event->pkt_size= size;
	recv_event->key_size = (u64) ctx->args[5];
	recv_event->queue_id = queue_id;

	recv_event->batch_idx = batch->current_upcall;
	recv_event->batch_ts = batch->leader_ts;
	return 0;
)

char __license[] SEC("license") = "GPL";
