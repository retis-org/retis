#include <common.h>
#include <ovs_common.h>

/* Hook for kprobe:ovs_execute_actions. */
DEFINE_HOOK(F_AND, RETIS_F_PACKET_PASS,
	u32 queue_id;
	u64 tid = bpf_get_current_pid_tgid();
	struct execute_actions_ctx ectx = {};
	struct sk_buff *skb;

	skb = retis_get_sk_buff(ctx);
	if (!skb)
		return -1;

	queue_id = queue_id_gen_skb(skb);

	if (bpf_map_lookup_elem(&flow_exec_tracking, &queue_id)) {
		/* Indicate this flow execution is the result of a userpace
		 * command */
		ectx.command = true;
	}
	bpf_map_delete_elem(&flow_exec_tracking, &queue_id);
	ectx.skb = skb;

	if (!bpf_map_update_elem(&inflight_exec, &tid, &ectx, BPF_ANY)) {
		return -1;
	}
	return 0;
)

char __license[] SEC("license") = "GPL";
