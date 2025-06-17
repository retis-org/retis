#include <common.h>
#include <ovs_common.h>

/* Hook for kprobe:ovs_flow_tbl_lookup_stats */
DEFINE_HOOK_RAW(
	struct execute_actions_ctx *ectx;
	u64 sb = ctx->stack_base;

	ectx = bpf_map_lookup_elem(&inflight_exec, &sb);
	if (!ectx) {
		return 0;
	}

	ectx->n_mask_hit = (u32 *)ctx->regs.reg[3];
	ectx->n_cache_hit = (u32 *)ctx->regs.reg[4];

	return 0;
)

char __license[] SEC("license") = "GPL";
