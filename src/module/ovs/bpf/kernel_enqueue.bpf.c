#include <openvswitch.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include <ovs_common.h>

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct upcall_enqueue_event {
	s32 ret;
	u8 cmd;
	u32 port;
	u64 upcall_ts;
	u32 upcall_cpu;
	u32 queue_id;
} __attribute__((packed));

static __always_inline u8 update_inflight_enqueue(u32 queue_id)
{
	uint32_t zero = 0;
	if (bpf_map_update_elem(&inflight_enqueue, &queue_id, &zero,
				BPF_NOEXIST)) {
		/* The entry already exists. This means an upcall was enqueued
		 * with the same queue_id and it has not been received (i.e
		 * dequeued) yet. It is likely we will have problems correlating
		 * events. TODO: report the error.*/
		return 1;
	}
	return 0;
}

/* Hook for kretprobe:queue_userspace_packet. */
DEFINE_HOOK_RAW(
	struct dp_upcall_info *upcall;
	struct sk_buff *skb;
	struct upcall_context *uctx;
	struct upcall_enqueue_event *enqueue;
	u64 tid = bpf_get_current_pid_tgid();

	/* Retrieve upcall context and store add it to the event so we can
	* group enqueue events to their upcall event.
	* If there is no upcall in flight (it may have been filtered out) ignore
	* this event as well. */
	uctx = bpf_map_lookup_elem(&inflight_upcalls, &tid);
	if (!uctx)
		return 0;

	skb = retis_get_sk_buff(ctx);
	if (!skb)
		return 0;

	upcall = (struct dp_upcall_info *) ctx->regs.reg[3];
	if (!upcall)
		return 0;

	enqueue = get_event_section(event, COLLECTOR_OVS, OVS_DP_UPCALL_QUEUE,
				    sizeof(*enqueue));
	if (!enqueue)
		return 0;

	enqueue->upcall_ts = uctx->ts;
	enqueue->upcall_cpu = uctx->cpu;
	enqueue->port = BPF_CORE_READ(upcall, portid);
	enqueue->cmd = BPF_CORE_READ(upcall, cmd);
	enqueue->ret = (int) ctx->regs.ret;
	enqueue->queue_id = queue_id_gen_skb(skb);

	update_inflight_enqueue(enqueue->queue_id);

	return 0;
)

char __license[] SEC("license") = "GPL";
