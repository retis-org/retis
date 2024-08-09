#ifndef __CORE_PROBE_KERNEL_BPF_COMMON_TYPES__
#define __CORE_PROBE_KERNEL_BPF_COMMON_TYPES__

#include <vmlinux.h>

#include <events.h>
#include <retis_context.h>

struct common_type_event {
	u32 type;
	u64 val;
};

enum common_type_id {
	SKB_DROP_REASON = 1,
	SK_RST_REASON,
};

static __always_inline void handle_drop_reason(struct retis_context *ctx,
					       struct retis_raw_event *event)
{
	struct common_type_event *e;

	if (!retis_arg_valid(ctx, skb_drop_reason))
		return;

	e = get_event_section(event, COMMON_TYPE, 1, sizeof(*e));
	if (!e)
		return;

	e->type = SKB_DROP_REASON;
	e->val = retis_get_skb_drop_reason(ctx);
}

static __always_inline void handle_rst_reason(struct retis_context *ctx,
					      struct retis_raw_event *event)
{
	struct common_type_event *e;

	if (!retis_arg_valid(ctx, sk_rst_reason))
		return;

	e = get_event_section(event, COMMON_TYPE, 1, sizeof(*e));
	if (!e)
		return;

	e->type = SK_RST_REASON;
	e->val = retis_get_sk_rst_reason(ctx);
}

static __always_inline void handle_common_types(struct retis_context *ctx,
						struct retis_raw_event *event)
{
	handle_drop_reason(ctx, event);
	handle_rst_reason(ctx, event);
}

#endif /* __CORE_PROBE_KERNEL_BPF_COMMON_TYPES__ */
