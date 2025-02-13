#include <common.h>
#include <ovs_common.h>
#include <skb_tracking.h>

#define MAX_UFID_LENGTH 16

struct flow_lookup_ret_event {
	BINDING_PTR(struct sw_flow *, flow);
	BINDING_PTR(struct sw_flow_actions *, sf_acts);
	u32 ufid[MAX_UFID_LENGTH / 4];
	u32 n_mask_hit;
	u32 n_cache_hit;
	u64 skb_orig_head;
	u64 skb_timestamp;
	u64 skb;
} __binding;

/* Hook for kretprobe:ovs_flow_tbl_lookup_stats */
DEFINE_HOOK_RAW(
	u64 tid = bpf_get_current_pid_tgid();
	struct flow_lookup_ret_event *ret;
	struct execute_actions_ctx *ectx;
	struct tracking_info *track;
	struct sw_flow *flow;
	u32 ufid_len = 0;

	ectx = bpf_map_lookup_elem(&inflight_exec, &tid);
	if (!ectx) {
		return 0;
	}

	flow = (struct sw_flow *)ctx->regs.ret;
	if (!flow) {
		/* No flows. This is most likely an upcall.
		 * There's no much we can do other than clean-up
		 * the map and return.
		 */
		bpf_map_delete_elem(&inflight_exec, &tid);
		return 0;
	}

	ufid_len = BPF_CORE_READ(flow, id.ufid_len);
	if (!ufid_len) {
		log_error("Expected ufid representation expected, found key");
		return 0;
	}

	track = skb_tracking_info(ectx->skb);
	if (!track) {
		return 0;
	}
	ret = get_event_section(event, COLLECTOR_OVS,
				OVS_FLOW_TBL_LOOKUP_RETURN,
				sizeof(*ret));
	if (!ret)
		return 0;

	if (BPF_CORE_READ_INTO(&ret->ufid, flow, id.ufid))
		log_error("Failed to read the ufid");

	ret->flow = flow;

	if (bpf_core_read(&ret->sf_acts, sizeof(ret->sf_acts), &flow->sf_acts))
		log_error("Failed to read sf_acts");

	/* Only log in case of failure while retrieving ancillary
	 * informations.
	 */
	if (bpf_probe_read_kernel(&ret->n_mask_hit, sizeof(ret->n_mask_hit),
				  ectx->n_mask_hit) < 0) {
		log_error("Failed to retrieve n_mask_hit");
	}

	if (bpf_probe_read_kernel(&ret->n_cache_hit, sizeof(ret->n_cache_hit),
				  ectx->n_cache_hit) < 0) {
		log_error("Failed to retrieve n_cache_hit");
	}

	ret->skb_orig_head = track->orig_head;
	ret->skb_timestamp = track->timestamp;
	ret->skb = (u64) ectx->skb;

	return 0;
)

char __license[] SEC("license") = "GPL";
