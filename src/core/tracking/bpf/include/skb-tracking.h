#ifndef __CORE_FILTERS_SKB_TRACKING__
#define __CORE_FILTERS_SKB_TRACKING__

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

/* Tracking configuration to provide hints about what the probed function does
 * for some special handling scenarios.
 *
 * Indexed in the tracking_config_map by the function ksym address.
 *
 * Please keep in sync with its Rust counterpart in module::skb_tracking.
 */
struct tracking_config {
	/* Function is freeing skbs */
	u8 free;
	/* Function is invalidating the head of skbs */
	u8 inv_head;
} __attribute__((packed));
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
 *
 * Please keep in sync with its Rust counterpart.
 */
struct tracking_info {
	/* When the skb was first seen */
	u64 timestamp;
	/* When the skb was last seen */
	u64 last_seen;
	/* Original head address; useful when the head is invalidated */
	u64 orig_head;
} __attribute__((packed));
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

/* Must be called with a valid skb pointer */
static __always_inline int track_skb(struct retis_context *ctx)
{
	struct tracking_info *ti = NULL, new;
	bool free = false, inv_head = false;
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
		free = cfg->free;
		inv_head = cfg->inv_head;
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
		ti = &new;
		ti->timestamp = ctx->timestamp;
		ti->last_seen = ctx->timestamp;
		ti->orig_head = head;

		/* No need to globally track it if the first time we see this
		 * skb is when it is freed.
		 */
		if (!free)
			bpf_map_update_elem(&tracking_map, &head, &new,
					    BPF_NOEXIST);
	}

	/* Track when we last saw this skb, as it'll be useful to garbage
	 * collect tracking map entries if we miss some events.
	 */
	ti->last_seen = ctx->timestamp;

	/* If the function invalidates the skb head, we can't know what will be
	 * the new head value. Temporarily track the skb using its skb address.
	 */
	if (inv_head)
		bpf_map_update_elem(&tracking_map, (u64 *)&skb, ti, BPF_NOEXIST);
	/* If the skb is freed, remove it from our tracking list. */
	else if (free)
		bpf_map_delete_elem(&tracking_map, &head);

	return 0;
}

/* Must be called with a valid skb pointer */
static __always_inline bool skb_is_tracked(struct sk_buff *skb)
{
	return skb_tracking_info(skb) != NULL;
}

#endif /* __CORE_FILTERS_SKB_TRACKING__ */
