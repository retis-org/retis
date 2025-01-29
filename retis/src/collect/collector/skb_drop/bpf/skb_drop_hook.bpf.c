#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

struct skb_drop_event {
	s32 drop_reason;
} __binding;

DEFINE_HOOK(F_AND, RETIS_ALL_FILTERS,
	struct skb_drop_event *e;

	/* Check if the kernel knows about skb drop reasons, and if so check we
	 * can retrieve it. This should be the common case. In case the kernel
	 * doesn't know skb drop reasons, this hook will generate fake events
	 * and will only be attached to specific hooks.
	 */
	if (bpf_core_type_exists(enum skb_drop_reason) &&
	    !retis_arg_valid(ctx, skb_drop_reason))
		return 0;

	e = get_event_section(event, COLLECTOR_SKB_DROP, 1, sizeof(*e));
	if (!e)
		return 0;

	e->drop_reason = bpf_core_type_exists(enum skb_drop_reason) ?
		retis_get_skb_drop_reason(ctx) : -1;

	return 0;
)

char __license[] SEC("license") = "GPL";
