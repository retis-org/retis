#include <common.h>
#include <ovs_common.h>

/* Hook for kprobe:ovs_execute_actions. */
DEFINE_HOOK(F_AND, RETIS_F_PACKET_PASS,
	u64 tid = bpf_get_current_pid_tgid();
	struct sk_buff *skb = retis_get_sk_buff(ctx);
	struct execute_actions_ctx ectx;
	ectx.skb = skb;

	if (!bpf_map_update_elem(&inflight_exec, &tid, &ectx, BPF_ANY)) {
		return -1;
	}
	return 0;
)

char __license[] SEC("license") = "GPL";
