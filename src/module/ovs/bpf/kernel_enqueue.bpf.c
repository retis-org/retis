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

static __always_inline u32 queue_id_gen(struct sk_buff *skb)
{
	int zero = 0;
	struct packet_buffer *buff = bpf_map_lookup_elem(&packet_buffers, &zero);
	if (!buff)
		return 0;

	return hash_skb(buff, skb);
}

/* Hook for kretprobe:queue_userspace_packet. */
DEFINE_HOOK(F_AND, RETIS_F_PACKET_PASS,
	struct dp_upcall_info *upcall;
	struct sk_buff *skb;
	struct upcall_context *uctx;
	struct upcall_enqueue_event *enqueue;
	u64 tid = bpf_get_current_pid_tgid();

	/* Retrieve upcall context and store add it to the event so we can
	* group enqueue events to their upcall event. */
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
	enqueue->queue_id = queue_id_gen(skb);

	return 0;
)

char __license[] SEC("license") = "GPL";
