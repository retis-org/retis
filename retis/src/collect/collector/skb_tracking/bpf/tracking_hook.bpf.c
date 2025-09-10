#include "stack_tracking.h"
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include <skb_tracking.h>

struct skb_tracking_event {
	u64 orig_head;
	u64 timestamp;
	u64 skb;
} __binding;

DEFINE_HOOK(F_AND, RETIS_ALL_FILTERS,
	struct skb_tracking_event *e;
	struct tracking_info *ti;
	struct sk_buff *skb;
	u64 skb_ref;

	skb = retis_get_sk_buff(ctx);

	if (!skb) {
		skb_ref = stack_get_skb_ref(ctx->stack_base);
		ti = skb_tracking_info(&skb_ref);
	} else {
		ti = skb_tracking_info_by_skb(skb);
	}

	if (!ti)
		return 0;

	e = get_event_section(event, COLLECTOR_SKB_TRACKING, 1, sizeof(*e));
	if (!e)
		return 0;

	e->orig_head = ti->orig_head;
	e->timestamp = ti->timestamp;
	e->skb = (u64)skb;

	return 0;
)

char __license[] SEC("license") = "GPL";
