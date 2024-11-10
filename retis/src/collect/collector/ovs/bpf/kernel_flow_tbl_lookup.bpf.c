#include <common.h>
#include <ovs_common.h>

/* Hook for kprobe:ovs_flow_tbl_lookup_stats */
DEFINE_HOOK_RAW(
	u64 tid = bpf_get_current_pid_tgid();
	struct execute_actions_ctx *ectx;

	ectx = bpf_map_lookup_elem(&inflight_exec, &tid);
	if (!ectx) {
		return 0;
	}

	ectx->n_mask_hit = (u32 *)ctx->regs.reg[3];
	ectx->n_cache_hit = (u32 *)ctx->regs.reg[4];

	return 0;
)

char __license[] SEC("license") = "GPL";
