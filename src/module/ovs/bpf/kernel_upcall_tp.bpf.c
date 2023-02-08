#include <openvswitch.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include "ovs_common.h"

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct upcall_event {
	u8 cmd;
	u32 port;
} __attribute__((packed));

/* Must be called with a valid upcall pointer */
static __always_inline int process_upcall(struct retis_context *ctx,
					  struct retis_raw_event *event,
					  struct dp_upcall_info *upcall)
{
	struct upcall_event *upcall_event =
		get_event_section(event, COLLECTOR_OVS, OVS_DP_UPCALL,
				  sizeof(*upcall_event));
	if (!upcall_event)
		return 0;

	upcall_event->port = BPF_CORE_READ(upcall, portid);
	upcall_event->cmd= BPF_CORE_READ(upcall, cmd);

	return 0;
}

/* Hook for raw_tracepoint:openvswitch:ovs_dp_upcall. */
DEFINE_HOOK(
	struct dp_upcall_info *upcall;

	upcall = (struct dp_upcall_info *) ctx->regs.reg[3];
	if (!upcall)
		return 0;

	process_upcall(ctx, event, upcall);

	return 0;
)

char __license[] SEC("license") = "GPL";
