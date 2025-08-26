#include <common.h>
#include <ovs_common.h>

/* Hook for kprobe:ovs_execute_actions. */
DEFINE_HOOK(F_AND, RETIS_F_PACKET_PASS,
	u32 queue_id;
	u64 tid = bpf_get_current_pid_tgid();
	struct execute_actions_ctx ectx = {};
	struct execute_actions_ctx *pectx;
	struct sk_buff *skb;

	skb = retis_get_sk_buff(ctx);
	if (!skb)
		return 0;

	pectx = bpf_map_lookup_elem(&inflight_exec, &tid);
	if (!pectx)
		pectx = &ectx;

	queue_id = queue_id_gen_skb(skb);

	if (bpf_map_lookup_elem(&flow_exec_tracking, &queue_id)) {
		/* Indicate this flow execution is the result of a userspace
		 * command and store the current queue_id so that further
		 * actions will use the same one regardless of packet
		 * modifications. */
		pectx->queue_id = queue_id;
		pectx->command = true;
	}
	bpf_map_delete_elem(&flow_exec_tracking, &queue_id);

	if (pectx->skb && pectx->skb != skb) {
		log_error("skb stored while processing differs when executing actions");
		pectx->skb = skb;
	}

	if ((pectx == &ectx) &&
	    !bpf_map_update_elem(&inflight_exec, &tid, pectx, BPF_ANY))
		return 0;

	return 0;
)

char __license[] SEC("license") = "GPL";
