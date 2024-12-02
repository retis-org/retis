#include <common.h>
#include <ovs_common.h>

/* Hook for kprobe:ovs_dp_process_packet. */
DEFINE_HOOK(F_AND, RETIS_ALL_FILTERS,
	u64 tid = bpf_get_current_pid_tgid();
	struct processing_ctx pctx = {};
	long err;

	pctx.skb = retis_get_sk_buff(ctx);
	if (!pctx.skb) {
		log_error("Invalid skb while ovs is processing the packet");
		return 0;
	}

	if ((err = bpf_map_update_elem(&inflight_processing, &tid, &pctx, BPF_ANY))) {
		log_error("Failed to set processing entry at index %lu with err: %lu", tid, err);
		return 0;
	}

	return 0;
)

char __license[] SEC("license") = "GPL";
