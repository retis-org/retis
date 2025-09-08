#ifndef __CORE_FILTERS_SKB_TRACKING__
#define __CORE_FILTERS_SKB_TRACKING__

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

#include <retis_context.h>
#include <stack_tracking.h>

/* Tracking configuration to provide hints about what the probed function does
 * for some special handling scenarios.
 *
 * Indexed in the tracking_config_map by the function ksym address.
 */
struct tracking_config {
	/* Function is freeing skbs */
	u8 free;
	/* Function is partially freeing skbs (head isn't freed but merge into
	 * another skb).
	 */
	u8 partial_free;
	/* Function is invalidating the head of skbs */
	u8 inv_head;
	/* Special case where no addition tracking data should be added by this
	 * probe. We can still read existing tracking data.
	 */
	u8 no_tracking;
} __packed __binding;
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROBE_MAX);
	__type(key, u64);
	__type(value, struct tracking_config);
} tracking_config_map SEC(".maps");

/* The tracking_info structure stores information on known skbs. It is indexed
 * in the tracking_map by the skb data address (and in some temporary cases by
 * the skb address directly).
 *
 * In order to uniquely identify skbs, the tuple (addr, timestamp) is used.
 */
struct tracking_info {
	/* When the skb was first seen */
	u64 timestamp;
	/* When the skb was last seen */
	u64 last_seen;
	/* Original head address; useful when the head is invalidated */
	u64 orig_head;
	/* Reference to stack_tracking_map */
	u64 stack_ref;
} __binding;
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, struct tracking_info);
} tracking_map SEC(".maps");

/* Must be called with a valid skb pointer */
static __always_inline struct tracking_info *skb_tracking_info(struct sk_buff *skb)
{
	struct tracking_info *ti = NULL;
	u64 head;

	head = (u64)BPF_CORE_READ(skb, head);
	if (!head)
		return 0;

	ti = bpf_map_lookup_elem(&tracking_map, &head);
	if (!ti)
		/* It might be temporarily stored it using its skb address. */
		ti = bpf_map_lookup_elem(&tracking_map, (u64 *)&skb);

	return ti;
}

static __always_inline int track_skb_start(struct retis_context *ctx)
{
	bool inv_head = false, no_tracking = false, free = false,
		deferred_update = false;
	struct tracking_info *ti = NULL, new;
	struct tracking_config *cfg;
	u64 head, ksym = ctx->ksym;
	struct sk_buff *skb;

	skb = retis_get_sk_buff(ctx);
	if (!skb)
		return 0;

	/* Try to retrieve the tracking configuration for this symbol. Only
	 * specific ones will be found while we want to track skb in all
	 * functions taking an skb as a parameter. When no tracking
	 * configuration is found, the function being probed is just quite
	 * generic.
	 */
	cfg = bpf_map_lookup_elem(&tracking_config_map, &ksym);
	if (cfg) {
		inv_head = cfg->inv_head;
		no_tracking = cfg->no_tracking;
		free = cfg->free;
	}

	head = (u64)BPF_CORE_READ(skb, head);
	if (!head)
		return 0;

	ti = bpf_map_lookup_elem(&tracking_map, &head);

	/* No tracking info was found for this skb. */
	if (!ti) {
		/* It might be temporarily stored it using its skb address. */
		ti = bpf_map_lookup_elem(&tracking_map, (u64 *)&skb);
		if (ti) {
			/* If found, index it by its data address from now on,
			 * as others.
			 */
			bpf_map_delete_elem(&tracking_map, (u64 *)&skb);
			bpf_map_update_elem(&tracking_map, &head, ti,
					    BPF_NOEXIST);
		}
	}

	/* Still NULL, this is the first time we see this skb. Create a new
	 * tracking info.
	 */
	if (!ti) {
		/* If running from a kretprobe, the skb could have been freed
		 * already. Do not add new tracking info.
		 *
		 * In some cases this could lead to an event from a kretprobe
		 * not being linked to later ones, if the skb was first seen
		 * there.
		 */
		if (ctx->probe_type == KERNEL_PROBE_KRETPROBE)
			return 0;

		/* Tracking info doesn't exist and we don't want to add one,
		 * nothing more we can do here.
		 */
		if (no_tracking)
			return 0;

		ti = &new;
		ti->timestamp = ctx->timestamp;
		ti->orig_head = head;
		ti->stack_ref = 0;

		deferred_update = true;
	}

	/* Track when we last saw this skb, as it'll be useful to garbage
	 * collect tracking map entries if we miss some events.
	 */
	ti->last_seen = ctx->timestamp;

	/* If the skb gets tracked but the stack_base doesn't match, it
	 * may mean that a packet got queued and handled in a
	 * different context in terms of stack.  cfg->free is an
	 * exception as we want to keep the old reference and consume
	 * it to delete the original stack_id entry in the case of
	 * deallocation happening in different contexts (e.g. deferred
	 * deallocation).
	 */
	if (!free && ti->stack_ref != ctx->stack_base)
		ti->stack_ref = track_stack_start(ctx->stack_base);

	if (deferred_update)
		bpf_map_update_elem(&tracking_map, &head, ti, BPF_NOEXIST);

	/* If the function invalidates the skb head, we can't know what will be
	 * the new head value. Temporarily track the skb using its skb address.
	 */
	if (inv_head)
		bpf_map_update_elem(&tracking_map, (u64 *)&skb, ti, BPF_NOEXIST);

	return 0;
}

static __always_inline int track_skb_end(struct retis_context *ctx)
{
	struct tracking_config *cfg;
	u64 head, ksym = ctx->ksym;
	struct tracking_info *ti;
	struct sk_buff *skb;

	cfg = bpf_map_lookup_elem(&tracking_config_map, &ksym);
	if (!cfg)
		return 0;

	/* We only supports free functions below */
	if (!cfg->free)
		return 0;

	skb = retis_get_sk_buff(ctx);
	if (!skb)
		return 0;

	head = (u64)BPF_CORE_READ(skb, head);
	if (!head)
		return 0;

	if (cfg->partial_free) {
		/* See kfree_skb_partial */
		bool stolen = retis_get_param(ctx, 1, bool);

		/* If the head wasn't stolen in a partial free, it will be freed
		 * later and we'll catch it.
		 */
		if (!stolen)
			return 0;
	}

	ti = bpf_map_lookup_elem(&tracking_map, &head);
	/* Remove the stack tracking entry only if the free is not
	 * deferred, otherwise this would be racy requiring some way
	 * to synchronize the access, meaning we try hard to not remove
	 * entries used elsewhere.
	 */
	if (ti && ctx->stack_base == ti->stack_ref)
		track_stack_end(ti->stack_ref);

	/* Skb is freed, remove it from our tracking list. */
	bpf_map_delete_elem(&tracking_map, &head);

	return 0;
}

/* Must be called with a valid skb pointer */
static __always_inline bool skb_is_tracked(struct sk_buff *skb)
{
	return skb_tracking_info(skb) != NULL;
}

#endif /* __CORE_FILTERS_SKB_TRACKING__ */
