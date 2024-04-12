#ifndef __CORE_PROBE_KERNEL_BPF_COMMON__
#define __CORE_PROBE_KERNEL_BPF_COMMON__

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include <common_defs.h>
#include <retis_context.h>
#include <events.h>
#include <helpers.h>
#include <packet_filter.h>
#include <meta_filter.h>
#include <skb_tracking.h>

/* Kernel section of the event data. */
struct kernel_event {
	u64 symbol;
	/* values from enum kernel_probe_type */
	u8 type;
	long stack_id;
} __attribute__((packed));

/* Per-probe configuration; keep in sync with its Rust counterpart in
 * core::probe::kernel::config.
 */
struct retis_probe_config {
	struct retis_probe_offsets offsets;
	u8 stack_trace;
} __attribute__((packed));

/* Probe configuration; the key is the target symbol address */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROBE_MAX);
	__type(key, u64);
	__type(value, struct retis_probe_config);
} config_map SEC(".maps");

/* Probe stack trace map. */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 4096);
	__uint(key_size, sizeof(u32));
	/* PERF_MAX_STACK_DEPTH times u64 for value size. */
	__uint(value_size, 127 * sizeof(u64));
} stack_map SEC(".maps");

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
 * DEFINE_HOOK(AND_OR_SEL, FILTER_FLAG1 | FILTER_FLAG2 | ...,
 *	do_something(ctx);
 *	return 0;
 * )
 *
 * char __license[] SEC("license") = "GPL";
 * ```
 *
 * Do not forget to add the hook to build.rs
 */
#define DEFINE_HOOK(fmode, fflags, statements)					\
	SEC("ext/hook")								\
	int hook(struct retis_context *ctx, struct retis_raw_event *event)	\
	{									\
		/* Let the verifier be happy */					\
		if (!ctx || !event)						\
			return 0;						\
		if (!((fmode == F_OR) ?						\
		      (ctx->filters_ret & (fflags)) :				\
		      ((ctx->filters_ret & (fflags)) == (fflags))))		\
			return 0;						\
		statements							\
	}

/* Helper that defines a hook that doesn't depend on any filtering
 * result and runs regardless.  Filtering outcome is still available
 * through ctx->filters_ret for actions that need special handling not
 * covered by DEFINE_HOOK([F_AND|F_OR], flags, ...).
 *
 * To define a hook in a collector hook, say hook.bpf.c,
 * ```
 * #include <common.h>
 *
 * DEFINE_HOOK_RAW(
 *	do_something(ctx);
 *	return 0;
 * )
 *
 * char __license[] SEC("license") = "GPL";
 * ```
 *
 * Do not forget to add the hook to build.rs
 */
#define DEFINE_HOOK_RAW(statements) DEFINE_HOOK(F_AND, 0, statements)

/* Number of hooks installed, used to micro-optimize the call chain */
const volatile u32 nhooks = 0;

/* Hook definition, aimed at being replaced before the program is attached. The
 * temporary retval is volatile to not let the compiler think he can optimize
 * it. Credits to the XDP dispatcher.
 */
#define HOOK(x)									\
	__attribute__ ((noinline))						\
	int hook##x(struct retis_context *ctx, struct retis_raw_event *event) {	\
		volatile int ret = 0;						\
		if (!ctx || !event)						\
			return 0;						\
		return ret;							\
	}
HOOK(0)
HOOK(1)
HOOK(2)
HOOK(3)
HOOK(4)
HOOK(5)
HOOK(6)
HOOK(7)
HOOK(8)
HOOK(9)
/* Keep in sync with its Rust counterpart in crate::core::probe::kernel */
#define HOOK_MAX 10

static __always_inline void filter(struct retis_context *ctx)
{
	struct retis_packet_filter_ctx fctx = {};
	struct sk_buff *skb;
	char *head;

	skb = retis_get_sk_buff(ctx);
	if (!skb)
		return;
	/* Special case the packet filtering logic if the skb is already
	 * tracked. This helps in may ways, including:
	 * - Performances.
	 * - Following packet transformations.
	 * - Filtering packets when the whole data isn't available anymore.
	 */
	if (skb_is_tracked(skb)) {
		ctx->filters_ret |= RETIS_ALL_FILTERS;
		return;
	}

	head = (char *)BPF_CORE_READ(skb, head);
	fctx.len = BPF_CORE_READ(skb, len);

	/* L3 filters require fewer loads (which means less overhead due to
	 * memory access) and can match in the case the mac_header is not
	 * present (i.e. early in the tx path).
	 * Despite this peculiarity, the current approach is conservative,
	 * favouring L2 filters over L3 when the mac_header is present.
	 */
	if (is_mac_data_valid(skb)) {
		fctx.data = head + BPF_CORE_READ(skb, mac_header);
		packet_filter(&fctx, FILTER_L2);
		goto filter_outcome;
	}

	if (!is_network_data_valid(skb))
		return;

	fctx.data = head + BPF_CORE_READ(skb, network_header);
	/* L3 filter can be a nop, meaning the criteria are not enough to
	 * express a match in terms of L3 only.
	 */
	packet_filter(&fctx, FILTER_L3);

	/* Due to a bug we can't use the return value of packet_filter(), but
	 * we have to rely on the value returned into the context.
	 */
filter_outcome:
	ctx->filters_ret |= (!!fctx.ret) << RETIS_F_PACKET_PASS_SH;
	ctx->filters_ret |= (!!meta_filter(skb)) << RETIS_F_META_PASS_SH;
}

/* The chaining function, which contains all our core probe logic. This is
 * called from each probe specific part after filling the common context and
 * just before returning.
 */
static __always_inline int chain(struct retis_context *ctx)
{
	struct retis_probe_config *cfg;
	struct retis_raw_event *event;
	/* volatile needed here to prevent from optimizing the
	 * event usage length read before and after the hook chain.
	 */
	struct common_task_event *ti;
	static bool enabled = false;
	volatile u16 pass_threshold;
	struct common_event *e;
	struct kernel_event *k;

	/* Check if the collection is enabled, otherwise bail out. Once we have
	 * a positive result, cache it.
	 */
	if (unlikely(!enabled)) {
		enabled = collection_enabled();
		if (!enabled)
			return 0;
	}

	cfg = bpf_map_lookup_elem(&config_map, &ctx->ksym);
	if (!cfg)
		return 0;

	ctx->offsets = cfg->offsets;

	filter(ctx);

	/* Track the skb. Note that this is done *after* filtering! If no skb is
	 * available this is a no-op.
	 *
	 * Important note: we must run this as soon as possible so the tracking
	 * logic runs even if later ops fail: we don't want to miss information
	 * because of non-fatal errors!
	 */
	if (RETIS_TRACKABLE(ctx->filters_ret))
		track_skb_start(ctx);

	/* Shortcut when there are no hooks (e.g. tracking-only probe); no need
	 * to allocate and fill an event to drop it later on.
	 */
	if (nhooks == 0)
		goto exit;

	event = get_event();
	if (!event) {
		err_report(ctx->ksym, 0);
		goto exit;
	}

	e = get_event_section(event, COMMON, COMMON_SECTION_CORE, sizeof(*e));
	if (!e)
		goto discard_event;

	e->timestamp = ctx->timestamp;
	e->smp_id = bpf_get_smp_processor_id();

	ti = get_event_zsection(event, COMMON, COMMON_SECTION_TASK, sizeof(*ti));
	if (!ti)
		goto discard_event;

	ti->pid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(ti->comm, sizeof(ti->comm));

	k = get_event_section(event, KERNEL, 1, sizeof(*k));
	if (!k)
		goto discard_event;

	k->symbol = ctx->ksym;
	k->type = ctx->probe_type;
	if (cfg->stack_trace)
		k->stack_id = bpf_get_stackid(ctx->orig_ctx, &stack_map, BPF_F_FAST_STACK_CMP);
	else
		k->stack_id = -1;

	pass_threshold = get_event_size(event);
	barrier_var(pass_threshold);

/* Defines the logic to call hooks one by one.
 *
 * As a temporary quirk we do handle -ENOMSG and drop the event in this case.
 * This should not be used too much and a proper long term solution should be
 * found. The use case is to let hooks do some filtering otherwise we can end up
 * being flooded with events in some cases as w/o this hooks can only filter
 * themselves.
 */
#define ENOMSG	42
#define CALL_HOOK(x)				\
	if (x < nhooks) {			\
		int ret = hook##x(ctx, event);	\
		if (ret == -ENOMSG)		\
			goto discard_event;	\
	}
	CALL_HOOK(0)
	CALL_HOOK(1)
	CALL_HOOK(2)
	CALL_HOOK(3)
	CALL_HOOK(4)
	CALL_HOOK(5)
	CALL_HOOK(6)
	CALL_HOOK(7)
	CALL_HOOK(8)
	CALL_HOOK(9)

	if (get_event_size(event) > pass_threshold)
		send_event(event);
	else
discard_event:
		discard_event(event);

exit:
	/* Cleanup stage while tracking an skb. If no skb is available this is a
	 * no-op.
	 */
	if (RETIS_TRACKABLE(ctx->filters_ret))
		track_skb_end(ctx);

	return 0;
}

#endif /* __CORE_PROBE_KERNEL_BPF_COMMON__ */
