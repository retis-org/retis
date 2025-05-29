#include <common.h>
#include <ovs_common.h>


/* Hook for extending the skb context in flow_tbl_lookup kretprobe */
DEFINE_CTX_HOOK(
	u64 tid = bpf_get_current_pid_tgid();
	struct execute_actions_ctx *ectx;

	if (retis_arg_valid(ctx, sk_buff))
		return 0;

	ectx = bpf_map_lookup_elem(&inflight_exec, &tid);
	if (!ectx)
		return 0;

	ctx->regs.reg[EXT_REG_SKB] = (u64)ectx->skb;
	ctx->offsets.sk_buff = EXT_REG_SKB;

	return 0;
)

char __license[] SEC("license") = "GPL";
