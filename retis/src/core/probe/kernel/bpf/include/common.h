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
#include <stack_tracking.h>

/* Kernel section of the event data. */
struct kernel_event {
	u64 symbol;
	long stack_id;
	/* values from enum kernel_probe_type */
	u8 type;
} __binding;

/* Per-probe configuration. */
struct retis_probe_config {
	struct retis_probe_offsets offsets;
	u8 stack_trace;
} __binding;

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

#define RETIS_TRACKABLE(ctx)	(!(ctx->filters_ret ^ RETIS_ALL_FILTERS))

/* Helper to define a hook (mostly in collectors) while not having to duplicate
 * the common part everywhere. This also ensure hooks are doing the right thing
 * and should help with maintenance.
 *
 * To define a hook in a collector hook, say hook.bpf.c,
 * ```
 * #include <common.h>
 *
 * DEFINE_NAMED_HOOK(hook_name, AND_OR_SEL, FILTER_FLAG1 | FILTER_FLAG2 | ...,
 *	do_something(ctx);
 *	return 0;
 * )
 *
 * char __license[] SEC("license") = "GPL";
 * ```
 *
 * Do not forget to add the hook to build.rs
 */
#define DEFINE_NAMED_HOOK(hook_name, fmode, fflags, statements)			\
	SEC("ext/hook")								\
	int hook_name(struct retis_context *ctx, struct retis_raw_event *event) \
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

/* Simple wrapper for DEFINE_NAMED_HOOK() that use file base name as
 * default name.
 */
#define DEFINE_HOOK(fmode, fflags, statements)				\
	DEFINE_NAMED_HOOK(__PROG_NAME, fmode, fflags, statements)

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
#define DEFINE_HOOK_RAW(statements)				\
	DEFINE_NAMED_HOOK(__PROG_NAME, F_AND, 0, statements)

/* Number of hooks installed, used to micro-optimize the call chain */
const volatile u32 nhooks = 0;

/* Hook definition, aimed at being replaced before the program is attached. The
 * temporary retval is volatile to not let the compiler think he can optimize
 * it. Credits to the XDP dispatcher.
 */
#define HOOK(x)									\
	__noinline								\
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

__noinline
int ctx_hook(struct retis_context *ctx)
{
	volatile int ret = 0;
	if (!ctx)
		return 0;
	return ret;
}

#define DEFINE_NAMED_CTX_HOOK(hook_name, statements)				\
	SEC("ext/hook")								\
	int hook_name(struct retis_context *ctx)				\
	{									\
		if (!ctx)							\
			return 0;						\
		statements							\
	}

#define DEFINE_CTX_HOOK(statements)				\
	DEFINE_NAMED_CTX_HOOK(__PROG_NAME, statements)

static __always_inline int extend_ctx_nft(struct retis_context *ctx)
{
	struct nft_traceinfo___6_3_0 *info_63;
	const struct nft_pktinfo *pkt;
	struct nft_traceinfo *info;

	if (retis_arg_valid(ctx, sk_buff) ||
	    !bpf_core_type_exists(struct nft_traceinfo) ||
	    !bpf_core_type_exists(struct nft_pktinfo))
		return 0;

	info = retis_get_nft_traceinfo(ctx);
	if (!info)
		return 0;

	info_63 = (struct nft_traceinfo___6_3_0 *)info;
	if (bpf_core_field_exists(info_63->pkt))
		pkt = BPF_CORE_READ(info_63, pkt);
	else
		pkt = retis_get_nft_pktinfo(ctx);

	if (pkt)
		retis_set_ext_sk_buff(ctx, BPF_CORE_READ(pkt, skb));

	return 0;
}

static __always_inline int extend_ctx(struct retis_context *ctx)
{
	void *orig_ctx;
	int ret;

	/* Builtin context extensions. */
	ret = extend_ctx_nft(ctx);
	if (ret)
		return ret;

	/* Builtin context extensions. */
	/* The verifier seems to have trouble keeping track of the type of
	 * the original context which. This seems to help.
	 */
	orig_ctx = ctx->orig_ctx;
	barrier_var(orig_ctx);
	ret = ctx_hook(ctx);
	ctx->orig_ctx = orig_ctx;

	return ret;
}

/* The template defines a placeholder instruction that will be
 * replaced on load with the actual filtering instructions.
 * Normally, if no filter gets set, a simple mov r0, 0x40000 will
 * replace the call. 0x40000 is used as it is also used by generated
 * cBPF filters, whereas 0 means no match, instead.
 * Ideally this function would be __naked, but apparently subprogs and
 * non-ctx arguments don't play well together during BTF generation.
 */
#define FILTER(x)								\
static __noinline unsigned int filter_##x(void *ctx)				\
{										\
	/* Not strictly required, but make sure r1 doesn't change for		\
	 * some reason.								\
	 */									\
	register void *ctx_reg asm("r1") = ctx;					\
	volatile unsigned int ret;						\
	asm volatile (								\
		"call " s(x) ";"						\
		"*(u32 *)%[ret] = r0"						\
		: [ret] "=m" (ret)						\
		: "r" (ctx_reg)							\
		: "r0", "r1", "r2", "r3", "r4",					\
		  "r5", "r6", "r7", "r8", "memory");				\
	return ret;								\
}
FILTER(l2)
FILTER(l3)
FILTER(meta)

static __always_inline u32 filter(struct sk_buff *skb)
{
	struct retis_packet_filter_ctx fctx = {};
	u32 filters_ret = 0;
	char *head;

	if (!skb)
		return 0;
	/* Special case the packet filtering logic if the skb is already
	 * tracked. This helps in may ways, including:
	 * - Performances.
	 * - Following packet transformations.
	 * - Filtering packets when the whole data isn't available anymore.
	 */
	if (skb_is_tracked(skb))
		return RETIS_ALL_FILTERS;

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
		filters_ret |=
			!!filter_l2(&fctx) << RETIS_F_PACKET_PASS_SH;
		goto next_filter;
	}

	if (!is_network_data_valid(skb))
		goto ret;

	fctx.data = head + BPF_CORE_READ(skb, network_header);
	/* L3 filter can be a nop, meaning the criteria are not enough to
	 * express a match in terms of L3 only.
	 */
	filters_ret |=
		!!filter_l3(&fctx) << RETIS_F_PACKET_PASS_SH;

next_filter:
	filters_ret |= !!filter_meta(skb) << RETIS_F_META_PASS_SH;
ret:
	return filters_ret;
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
	struct sk_buff *skb;
	int ret;

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

	ret = extend_ctx(ctx);
	if (ret)
		log_warning("ctx extension failed: %d", ret);

	skb = retis_get_sk_buff(ctx);
	if (skb)
		ctx->filters_ret = filter(skb);

	/* Track the skb. Note that this is done *after* filtering! If no skb is
	 * available this is a no-op.
	 *
	 * Important note: we must run this as soon as possible so the tracking
	 * logic runs even if later ops fail: we don't want to miss information
	 * because of non-fatal errors!
	 */
	if (RETIS_TRACKABLE(ctx))
		track_skb_start(ctx);
	else if (skb)
		/* Terminate any potentially existing entry not
		 * associated with a tracked skb. Blind termination
		 * approach is supposed to be more performing in the
		 * worst case and will lead to a simple lookup failure
		 * in most cases. This acts as packet path garbage
		 * collection (e.g. skb_tracking stale entry hanging).
		 */
		track_stack_end(ctx->stack_base);

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

	k = get_event_section(event, KERNEL, 0, sizeof(*k));
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
	if (RETIS_TRACKABLE(ctx))
		track_skb_end(ctx);

	return 0;
}

#endif /* __CORE_PROBE_KERNEL_BPF_COMMON__ */
