#include <openvswitch.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include "ovs_common.h"

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct upcall_enqueue_event {
	int ret;
	u8 cmd;
	u32 port;
	u64 upcall_ts;
	u32 upcall_cpu;
} __attribute__((packed));

/* Hook for kretprobe:queue_userspace_packet. */
DEFINE_HOOK(
	struct dp_upcall_info *upcall;
	struct upcall_context *uctx;
	u64 tid = bpf_get_current_pid_tgid();

	upcall = (struct dp_upcall_info *) ctx->regs.reg[3];
	if (!upcall)
		return 0;

	struct upcall_enqueue_event *enqueue =
		get_event_section(event, COLLECTOR_OVS, OVS_DP_UPCALL_QUEUE ,
				  sizeof(*enqueue));
	if (!enqueue)
		return 0;

	enqueue->port = BPF_CORE_READ(upcall, portid);
	enqueue->cmd= BPF_CORE_READ(upcall, cmd);
	enqueue->ret = (int) ctx->regs.ret;

	/* Retrieve upcall context and store add it to the event so we can
	* group enqueue events to their upcall event. */
	uctx = bpf_map_lookup_elem(&inflight_upcalls, &tid);
	if (uctx) {
		enqueue->upcall_ts = uctx->ts;
		enqueue->upcall_cpu = uctx->cpu;
	}
	return 0;
)

char __license[] SEC("license") = "GPL";
