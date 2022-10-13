#ifndef __CORE_PROBE_TYPE_BPF_COMMON__
#define __CORE_PROBE_TYPE_BPF_COMMON__

#include "events.h"

/*
 * Probe configuration.
 */

#define PROBES_MAX		128

struct probe_config {
	/* bitmap of what the probe supports */
#define PROBE_CAP_SK_BUFF	(1 << 0)
	u64 capabilities;

	s32 skb_offset;
};

/* Probe configuration; the key is the target symbol address */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROBES_MAX);
	__type(key, u64);
	__type(value, struct probe_config);
} config_map SEC(".maps");

/* 
 * Hooks and related definitions (e.g. trace context).
 */

struct regs {
#define PARAM_MAX 12	/* Currently fexit */
	u64 param[PARAM_MAX];
	u32 num;
};

struct trace_context {
	u64 timestamp;
	u64 ksym;
	struct regs regs;
	s32 skb_offset;
};

#define get_param(ctx, offset, type)							\
	(type)(((offset) >= 0 && (offset) < PARAM_MAX && (offset) < ctx->regs.num) ?	\
	ctx->regs.param[offset] : 0)

#define get_skb(ctx)							\
	(ctx->skb_offset >= 0 ?					\
	 get_param(ctx, ctx->skb_offset, struct sk_buff *) : 0)

#define FILTER(x)				\
__attribute__ ((noinline))			\
int filter##x(struct trace_context *ctx) {	\
	volatile int ret = 0;			\
	if (!ctx)				\
		return 0;			\
	return ret;				\
}
FILTER(0)
FILTER(1)

struct hook_config {
	u8 or;
	u8 filter_mask;
	u64 capabilities;
};

const volatile u32 hook_max = 0;
#define HOOK(x)							\
__attribute__ ((noinline))					\
int hook##x(struct trace_context *ctx, struct event *event) {	\
	volatile int ret = 0;					\
	if (!ctx || !event)					\
		return 0;					\
	return ret;						\
}								\
const volatile struct hook_config hook##x_cfg;
HOOK(0)
HOOK(1)

static __always_inline int chain(struct trace_context *ctx)
{
	struct probe_config *cfg;
	struct event *event;
	u64 key = ctx->ksym;
	u8 filter_mask = 0;

	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg)
		return 0;

	ctx->skb_offset = cfg->skb_offset;

	event = bpf_ringbuf_reserve(&event_map, sizeof(*event), 0);
	if (!event)
		return 0;

	event->ksym = ctx->ksym;
	event->timestamp = ctx->timestamp;

	filter_mask |= filter0(ctx) << 0;
	filter_mask |= filter1(ctx) << 1;

#if 0
// TODO: what if hook_cfg.filter_mask == 0?
#define RUN_HOOK(x)									\
	if (x <= hook_max &&								\
	    (hook##x_cfg.capabilities & cfg->capabilities) == hook##x_cfg.capabilities &&\
	    hook##x_cfg.or ? hook##x_cfg.filter_mask & filter_mask :			\
	    (hook##x_cfg.filter_mask & filter_mask) == hook##x_cfg.filter_mask)		\
		hook##x(ctx, event);

	RUN_HOOK(0)
	RUN_HOOK(1)
#else
	hook0(ctx, event);
	hook1(ctx, event);
#endif

	bpf_ringbuf_submit(event, 0);
	return 0;
}

#endif /* __CORE_PROBE_TYPE_BPF_COMMON__ */
