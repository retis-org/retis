#ifndef __CORE_PROBE_KERNEL_BPF_COMMON__
#define __CORE_PROBE_KERNEL_BPF_COMMON__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "events.h"

/* Kernel section of the event data. */
struct kernel_event {
	u64 symbol;
} __attribute__((packed));

/* Per-probe parameter offsets; keep in sync with its Rust counterpart in
 * core::probe::kernel::config. A value of -1 means the argument isn't
 * available. Please try to reuse the targeted object names.
 */
struct trace_probe_offsets {
	s8 sk_buff;
	s8 skb_drop_reason;
	s8 net_device;
	s8 net;		/* netns */
};

/* Per-probe configuration; keep in sync with its Rust counterpart in
 * core::probe::kernel::config.
 */
struct trace_probe_config {
	struct trace_probe_offsets offsets;
};

/* Keep in sync with its Rust counterpart in crate::core::probe::kernel */
#define PROBE_MAX	128

/* Probe configuration; the key is the target symbol address */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROBE_MAX);
	__type(key, u64);
	__type(value, struct trace_probe_config);
} config_map SEC(".maps");

/* Common representation of the register values provided to the probes, as this
 * is done in a per-probe type fashion.
 *
 * reg: registers values.
 * num: number of valid registers.
 */
struct trace_regs {
#define REG_MAX 12	/* Fexit max, let's use this */
	u64 reg[REG_MAX];
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
struct trace_context {
	u64 timestamp;
	u64 ksym;
	struct trace_probe_offsets offsets;
	struct trace_regs regs;
};

/* Helper to retrieve a function parameter argument using the common context */
#define trace_get_param(ctx, offset, type)	\
	(type)(((offset) >= 0 && (offset) < REG_MAX && (offset) < ctx->regs.num) ?	\
       ctx->regs.reg[offset] : 0)

/* Check if a given argument is valid */
#define trace_arg_valid(ctx, name)	\
	(ctx->offsets.name >= 0)

/* Argument specific helpers for use in generic hooks (and easier use in
 * targeted ones.
 */
#define TRACE_GET(ctx, name, type)		\
	(trace_arg_valid(ctx, name) ?		\
	 trace_get_param(ctx, ctx->offsets.name, type) : 0)

#define trace_get_sk_buff(ctx)		\
	TRACE_GET(ctx, sk_buff, struct sk_buff *)
#define trace_get_skb_drop_reason(ctx)	\
	TRACE_GET(ctx, skb_drop_reason, enum skb_drop_reason)
#define trace_get_net_device(ctx)	\
	TRACE_GET(ctx, net_device, struct net_device *)
#define trace_get_net(ctx)		\
	TRACE_GET(ctx, net, struct net *)

/* Helper to define a hook (mostly in collectors) while not having to duplicate
 * the common part everywhere. This also ensure hooks are doing the right thing
 * and should help with maintenance.
 *
 * To define a hook in a collector hook, say hook.bpf.c,
 * ```
 * #include <common.h>
 *
 * DEFINE_HOOK(
 *	do_something(ctx);
 *	return 0;
 * )
 *
 * char __license[] SEC("license") = "GPL";
 * ```
 *
 * Do not forget to add the hook to build.rs
 */
#define DEFINE_HOOK(inst)							\
	SEC("ext/hook")								\
	int hook(struct trace_context *ctx, struct trace_raw_event *event)	\
	{									\
		/* Let the verifier be happy */					\
		if (!ctx || !event)						\
			return 0;						\
		inst								\
	}

/* Number of hooks installed, used to micro-optimize the call chain */
const volatile u32 nhooks = 0;

/* Hook definition, aimed at being replaced before the program is attached. The
 * temporary retval is volatile to not let the compiler think he can optimize
 * it. Credits to the XDP dispatcher.
 */
#define HOOK(x)									\
	__attribute__ ((noinline))						\
	int hook##x(struct trace_context *ctx, struct trace_raw_event *event) {	\
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

/* The chaining function, which contains all our core probe logic. This is
 * called from each probe specific part after filling the common context and
 * just before returning.
 */
static __always_inline int chain(struct trace_context *ctx)
{
	struct trace_probe_config *cfg;
	struct trace_raw_event *event;
	struct common_event *e;
	struct kernel_event *k;

	cfg = bpf_map_lookup_elem(&config_map, &ctx->ksym);
	if (!cfg)
		return 0;

	ctx->offsets = cfg->offsets;

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

	send_event(event);
	return 0;
}

#endif /* __CORE_PROBE_KERNEL_BPF_COMMON__ */
