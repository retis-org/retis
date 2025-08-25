#include <common.h>
#include <ovs_common.h>

/* Hook for kprobe:ovs_dp_process_packet. */
DEFINE_HOOK(F_AND, RETIS_ALL_FILTERS,
	struct execute_actions_ctx ectx = {};
	u64 sb = ctx->stack_base;

	ectx.skb = retis_get_sk_buff(ctx);
	if (!ectx.skb) {
		log_error("Invalid skb while ovs is processing the packet");
		return 0;
	}

	if (!bpf_map_update_elem(&inflight_exec, &sb, &ectx, BPF_ANY))
		return 0;

	return 0;
)

char __license[] SEC("license") = "GPL";
