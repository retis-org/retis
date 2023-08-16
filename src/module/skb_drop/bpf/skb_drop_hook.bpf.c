#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

struct skb_drop_event {
	s32 drop_reason;
} __attribute__((packed));

DEFINE_HOOK(F_AND, RETIS_F_PACKET_PASS,
	struct skb_drop_event *e;

	e = get_event_section(event, COLLECTOR_SKB_DROP, 1, sizeof(*e));
	if (!e)
		return 0;

	if (bpf_core_type_exists(enum skb_drop_reason)) {
		if (!retis_arg_valid(ctx, skb_drop_reason))
			return 0;
		e->drop_reason = retis_get_skb_drop_reason(ctx);
	} else {
		e->drop_reason = -1;
	}

	return 0;
)

char __license[] SEC("license") = "GPL";
