#ifndef __CORE_PROBE_KERNEL_BPF_COMMON__
#define __CORE_PROBE_KERNEL_BPF_COMMON__

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include <common_defs.h>
#include <retis_context.h>
#include <events.h>
#include <helpers.h>
#include <hooks.h>
#include <packet_filter.h>
#include <meta_filter.h>
#include <skb_tracking.h>

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
	if (hooks.len == 0)
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

	if (call_hooks(ctx, event) == -ENOMSG)
		goto discard_event;

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
