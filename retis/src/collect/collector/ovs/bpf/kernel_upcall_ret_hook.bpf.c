#include <common.h>
#include <ovs_common.h>

struct upcall_ret_event {
	u64 upcall_ts;
	u32 upcall_cpu;
	int ret;
} __binding;

/* Hook for kretprobe:ovs_dp_upcall */
DEFINE_HOOK(F_AND, RETIS_ALL_FILTERS,
	struct upcall_ret_event *ret;
	struct upcall_context *uctx;
	u64 sb = ctx->stack_base;

	uctx = bpf_map_lookup_elem(&inflight_upcalls, &sb);
	if (uctx) {
		bpf_map_delete_elem(&inflight_upcalls, &sb);
		ret = get_event_section(event, COLLECTOR_OVS,
					OVS_DP_UPCALL_RETURN,
					sizeof(*ret));
		if (!ret)
			return 0;
		ret->upcall_ts = uctx->ts;
		ret->upcall_cpu = uctx->cpu;
		ret->ret = (int) ctx->regs.ret;
	}
	return 0;
)

char __license[] SEC("license") = "GPL";
