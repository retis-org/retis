#ifndef __CORE_PROBE_KERNEL_BPF_HOOKS__
#define __CORE_PROBE_KERNEL_BPF_HOOKS__

#include <events.h>
#include <retis_context.h>

#define RETIS_F_PASS(f, v)			\
	RETIS_F_##f##_PASS_SH = v,		\
	RETIS_F_##f##_PASS = 1 << v

/* Defines the bit position for each filter */
enum {
	RETIS_F_PASS(PACKET, 0),
	RETIS_F_PASS(META, 1),
};

/* Filters chain is an and */
#define F_AND		0
/* Filters chain is an or */
#define F_OR		1

#define RETIS_ALL_FILTERS	(RETIS_F_PACKET_PASS | RETIS_F_META_PASS)
#define RETIS_TRACKABLE(mask)	(!(mask ^ RETIS_ALL_FILTERS))

/* Helper to define a hook (mostly in collectors) while not having to duplicate
 * the common part everywhere. This also ensure hooks are doing the right thing
 * and should help with maintenance.
 *
 * To define a hook in a collector hook, say hook.bpf.c,
 * ```
 * #include <common.h>
 *
 * DEFINE_HOOK(name, AND_OR_SEL, FILTER_FLAG1 | FILTER_FLAG2 | ...,
 *	do_something(ctx);
 *	return 0;
 * )
 * ```
 * Do not forget to add the hook to hooks.h
 */
#define DEFINE_HOOK(name, fmode, fflags, statements)					\
	static __always_inline								\
	int hook_##name(struct retis_context *ctx, struct retis_raw_event *event)	\
	{										\
		/* Let the verifier be happy */						\
		if (!ctx || !event)							\
			return 0;							\
		if (!((fmode == F_OR) ?							\
		     (ctx->filters_ret & (fflags)) :					\
		     ((ctx->filters_ret & (fflags)) == (fflags))))			\
			return 0;							\
		statements								\
	}

/* Helper that defines a hook that doesn't depend on any filtering
 * result and runs regardless.  Filtering outcome is still available
 * through ctx->filters_ret for actions that need special handling not
 * covered by DEFINE_HOOK(name, [F_AND|F_OR], flags, ...).
 *
 * To define a hook in a collector hook, say hook.bpf.c,
 * ```
 * #include <common.h>
 *
 * DEFINE_HOOK_RAW(name,
 *	do_something(ctx);
 *	return 0;
 * )
 * ```
 *
 * Do not forget to add the hook to hooks.h
 */
#define DEFINE_HOOK_RAW(name, statements) DEFINE_HOOK(name, F_AND, 0, statements)

/* As a temporary quirk we do handle -ENOMSG and drop the event in this case.
 * This should not be used too much and a proper long term solution should be
 * found. The use case is to let hooks do some filtering otherwise we can end up
 * being flooded with events in some cases as w/o this hooks can only filter
 * themselves.
 */
#define ENOMSG 42

#include "tracking_hook.bpf.c"
#include "skb_drop_hook.bpf.c"
#include "skb_hook.bpf.c"
#include "ct.bpf.c"
#include "nft.bpf.c"

const volatile struct hooks {
	u32 len;
	u8 skb_tracking;
	u8 skb_drop;
	u8 skb;
	u8 ct;
	u8 nft;
} __binding hooks = {};

static __always_inline int call_hooks(struct retis_context *ctx,
				      struct retis_raw_event *event)
{
	int ret;

#define CALL_HOOK(name)				\
	if (hooks.name) {			\
		ret = hook_##name(ctx, event);	\
		if (ret)			\
			return ret;		\
	}

	CALL_HOOK(skb_tracking)
	CALL_HOOK(skb_drop)
	CALL_HOOK(skb)
	CALL_HOOK(ct)
	CALL_HOOK(nft)
//	CALL_HOOK(ovs)

	return 0;
}

#endif /* __CORE_PROBE_KERNEL_BPF_HOOKS__ */
