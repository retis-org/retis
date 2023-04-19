#ifndef __CORE_PROBE_KERNEL_BPF_COMMON__
#define __CORE_PROBE_KERNEL_BPF_COMMON__

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include <events.h>
#include <helpers.h>
#include <packet-filter.h>

enum kernel_probe_type {
	KERNEL_PROBE_KPROBE = 0,
	KERNEL_PROBE_KRETPROBE = 1,
	KERNEL_PROBE_TRACEPOINT = 2,
};

/* Kernel section of the event data. */
struct kernel_event {
	u64 symbol;
	/* values from enum kernel_probe_type */
	u8 type;
	long stack_id;
} __attribute__((packed));

/* Per-probe parameter offsets; keep in sync with its Rust counterpart in
 * core::probe::kernel::config. A value of -1 means the argument isn't
 * available. Please try to reuse the targeted object names.
 */
struct retis_probe_offsets {
	s8 sk_buff;
	s8 skb_drop_reason;
	s8 net_device;
	s8 net;		/* netns */
} __attribute__((packed));

/* Per-probe configuration; keep in sync with its Rust counterpart in
 * core::probe::kernel::config.
 */
struct retis_probe_config {
	struct retis_probe_offsets offsets;
	u8 stack_trace;
} __attribute__((packed));

/* Keep in sync with its Rust counterpart in crate::core::probe::kernel */
#define PROBE_MAX	128

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
	__uint(max_entries, 256);
	__uint(key_size, sizeof(u32));
	/* PERF_MAX_STACK_DEPTH times u64 for value size. */
	__uint(value_size, 127 * sizeof(u64));
} stack_map SEC(".maps");

/* Common representation of the register values provided to the probes, as this
 * is done in a per-probe type fashion.
 *
 * reg: registers values.
 * num: number of valid registers.
 */
struct retis_regs {
#define REG_MAX 12	/* Fexit max, let's use this */
	u64 reg[REG_MAX];
	u64 ret;
	u32 num;
};

/* Common context information consumed by all hooks. It serves as an abstraction
 * as different probe types have different specific contexts. This information
 * will be used to provide helpers for hooks as well, e.g. to safely retrieve a
 * function parameter.
 *
 * timestamp: Timestamp of when the probe wall called, should be filled as early
 *            as possible in the probe specific part. Then it should be left
 *            untouched.
 * ksym:      Symbol address of the where the probe was hooked. Should also be
 *            filled in the probe specific part. It is quite handy as it is the
 *            only common way of understanding where a probe/hook is running.
 * regs:      Common representation of the regs of the function being probed. It
 *            can be used to retrieve parameters, and if the probe type allows,
 *            the returned value. Should be accessed using the get_param()
 *            helper.
 */
struct retis_context {
	enum kernel_probe_type probe_type;
	u64 timestamp;
	u64 ksym;
	struct retis_probe_offsets offsets;
	struct retis_regs regs;
	/* Pointer to the original ctx. Needed for helper calls. */
	void *orig_ctx;
	/* Contains the bits identifying what filters yield a hit outcome.
	 * A bit is set means that the filter matched the data based on its
	 * criteria .
	 */
	u32 filters_ret;
};

#define RETIS_F_PASS(f, v)			\
	RETIS_F_##f##_PASS_SH = v,		\
	RETIS_F_##f##_PASS = 1 << v

/* Defines the bit position for each filter */
enum {
	RETIS_F_PASS(PACKET, 0),
};

/* Helper to retrieve a function parameter argument using the common context */
#define retis_get_param(ctx, offset, type)	\
	(type)(((offset) >= 0 && (offset) < REG_MAX && (offset) < ctx->regs.num) ?	\
       ctx->regs.reg[offset] : 0)

/* Check if a given argument is valid */
#define retis_arg_valid(ctx, name)	\
	(ctx->offsets.name >= 0)

/* Argument specific helpers for use in generic hooks (and easier use in
 * targeted ones.
 */
#define RETIS_GET(ctx, name, type)		\
	(retis_arg_valid(ctx, name) ?		\
	 retis_get_param(ctx, ctx->offsets.name, type) : 0)

#define retis_get_sk_buff(ctx)		\
	RETIS_GET(ctx, sk_buff, struct sk_buff *)
#define retis_get_skb_drop_reason(ctx)	\
	RETIS_GET(ctx, skb_drop_reason, enum skb_drop_reason)
#define retis_get_net_device(ctx)	\
	RETIS_GET(ctx, net_device, struct net_device *)
#define retis_get_net(ctx)		\
	RETIS_GET(ctx, net, struct net *)

/* Filters chain is an and */
#define F_AND		0
/* Filters chain is an or */
#define F_OR		1

#include <skb-tracking.h>

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

/* Always return true. Use 0x40000 as it's typically used by
 * generated filters while 0 means no match, instead.
 */
__attribute__ ((noinline))
unsigned int packet_filter(struct retis_filter_context *ctx)
{
	if (!ctx)
		return 0;

	ctx->ret = 0x40000;

	return ctx->ret;
}

static __always_inline char *skb_mac_header(struct sk_buff *skb)
{
	char *head = (char *)BPF_CORE_READ(skb, head);
	u16 mh = BPF_CORE_READ(skb, mac_header);

	if (mh == (u16)~0)
		return NULL;

	return head + mh;
}

static __always_inline void filter(struct retis_context *ctx)
{
	struct retis_filter_context fctx = {};
	struct sk_buff *skb;

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
		ctx->filters_ret |= RETIS_F_PACKET_PASS;
		return;
	}

	fctx.data = skb_mac_header(skb);
	if (fctx.data == NULL)
		return;

	fctx.len = BPF_CORE_READ(skb, len);
	/* Due to a bug we can't use the return value of packet_filter(), but
	 * we have to rely on the value returned into the context.
	 */
	packet_filter(&fctx);
	ctx->filters_ret |= (!!fctx.ret) << RETIS_F_PACKET_PASS_SH;
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
	volatile u16 pass_threshold;
	struct common_event *e;
	struct kernel_event *k;

	cfg = bpf_map_lookup_elem(&config_map, &ctx->ksym);
	if (!cfg)
		return 0;

	ctx->offsets = cfg->offsets;

	filter(ctx);

	event = get_event();
	if (!event)
		return 0;

	e = get_event_section(event, COMMON, 1, sizeof(*e));
	if (!e) {
		discard_event(event);
		return 0;
	}

	e->timestamp = ctx->timestamp;

	k = get_event_section(event, KERNEL, 1, sizeof(*k));
	if (!k) {
		discard_event(event);
		return 0;
	}

	k->symbol = ctx->ksym;
	k->type = ctx->probe_type;
	if (cfg->stack_trace)
		k->stack_id = bpf_get_stackid(ctx->orig_ctx, &stack_map, BPF_F_FAST_STACK_CMP);
	else
		k->stack_id = -1;


	/* Track the skb. Note that this is done *after* filtering! If no skb is
	 * available this is a no-op.
	 */
	if (ctx->filters_ret & RETIS_F_PACKET_PASS)
		track_skb(ctx);

	pass_threshold = get_event_size(event);

#define CALL_HOOK(x)		\
	if (x < nhooks)		\
		hook##x(ctx, event);
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

	if (get_event_size(event) <= pass_threshold)
		discard_event(event);
	else
		send_event(event);

	return 0;
}

#endif /* __CORE_PROBE_KERNEL_BPF_COMMON__ */
