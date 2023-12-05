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
};

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

#define RETIS_F_PASS(f, v)			\
	RETIS_F_##f##_PASS_SH = v,		\
	RETIS_F_##f##_PASS = 1 << v

/* Defines the bit position for each filter */
enum {
	RETIS_F_PASS(PACKET, 0),
};

/* Filters chain is an and */
#define F_AND		0
/* Filters chain is an or */
#define F_OR		1

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

#define FILTER_MAX_INSNS 4096

#define __s(v) #v
#define s(v) __s(v)

/* Reserve FILTER_MAX_INSNS - (instruction placeholder) */
#define RESERVE_NOP				\
	".rept " s(FILTER_MAX_INSNS) " - 1;"	\
	"goto +0x0;"				\
	".endr;"

/* Keep in sync with its Rust counterpart in
 * crate::core::filters::packets::ebpf
 */
#define STACK_RESERVED		8
#define SCRATCH_MEM_SIZE	4
/* 8 bytes for probe_read_kernel() outcome plus 16 * 4 scratch
 * memory locations for cbpf filters. Aligned to u64 boundary.
 */
#define SCRATCH_MEM_START	16 * SCRATCH_MEM_SIZE + STACK_RESERVED

#define STACK_SIZE		SCRATCH_MEM_START

/* The function defines a placeholder instruction and a nop frame that
 * will be replaced on load with the actual filtering
 * instructions. Normally, if no filter gets set, a simple mov r0,
 * 0x40000 will replace the call. 0x40000 is used as it is also used
 * by generated cBPF filters, whereas 0 means no match, instead. The
 * exceeding nops will get removed from the kernel during the load.
 * If no explicit, nor default filter gets set, call 0xdeadbeef will
 * fail to load and the verifier will report an error.
 */
static __always_inline
unsigned int packet_filter(struct retis_filter_context *ctx)
{
	register struct retis_filter_context *ctx_reg asm("r1");
	u8 stack[STACK_SIZE] __attribute__ ((aligned (8)));
	register u64 *fp asm("r9");

	if (!ctx)
		return 0;

	ctx_reg = ctx;
	fp = (u64 *)((void *)stack + sizeof(stack));

	asm volatile (
		"call 0xdeadbeef;"
		RESERVE_NOP
		"*(u32 *)%0 = r0;"
		: /* out */
		  "=m" (ctx->ret)
		: /* in */
		  "r" (ctx_reg),
		  "r" (fp)
		: "r0", "r1", "r2", "r3",
		  "r4", "r5", "r6", "r7",
		  "r8", "r9");

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
	struct common_task_event *ti;
	volatile u16 pass_threshold;
	struct common_event *e;
	struct kernel_event *k;

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
	if (ctx->filters_ret & RETIS_F_PACKET_PASS)
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
	if (ctx->filters_ret & RETIS_F_PACKET_PASS)
		track_skb_end(ctx);

	return 0;
}

#endif /* __CORE_PROBE_KERNEL_BPF_COMMON__ */
