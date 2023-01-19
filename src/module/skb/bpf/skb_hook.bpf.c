#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

#define BIT(x) (1 << (x))

/* Skb raw event sections.
 *
 * Please keep in sync with its Rust counterpart in module::skb::bpf.
 */
#define COLLECT_L2		0

/* Skb hook configuration. A map is used to set the config from userspace.
 *
 * Please keep in sync with its Rust counterpart in module::skb::bpf.
 */
struct skb_config {
	u64 sections;
} __attribute__((packed));
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, sizeof(struct skb_config));
} skb_config_map SEC(".maps");

/* Please keep the following structs in sync with its Rust counterpart in
 * module::skb::bpf.
 */
struct skb_l2_event {
	u8 dst[6];
	u8 src[6];
	u16 etype;
} __attribute__((packed));

/* Must be called with a valid skb pointer */
static __always_inline int process_skb_l2_l4(struct trace_context *ctx,
					     struct event *event,
					     struct skb_config *cfg,
					     struct sk_buff *skb)
{
	unsigned char *head = BPF_CORE_READ(skb, head);
	u16 mac, network, transport, etype;
	u8 protocol, ip_version;

	/* L2 */

	mac = BPF_CORE_READ(skb, mac_header);
	etype = BPF_CORE_READ(skb, protocol);

	/* If the ethertype isn't set, bail out early as we can't process such
	 * packets below.
	 */
	if (etype == 0)
		return 0;

	if (cfg->sections & BIT(COLLECT_L2)) {
		struct skb_l2_event *e =
			get_event_zsection(event, COLLECTOR_SKB, COLLECT_L2,
					   sizeof(*e));
		if (!e)
			return 0;

		if (mac != (u16)~0U) {
			struct ethhdr *eth = (struct ethhdr *)(head + mac);

			bpf_probe_read_kernel(e->src, sizeof(e->src), eth->h_source);
			bpf_probe_read_kernel(e->dst, sizeof(e->dst), eth->h_dest);
		}

		e->etype = etype;
	}

	return 0;
}

/* Must be called with a valid skb pointer */
static __always_inline int process_skb(struct trace_context *ctx,
				       struct event *event, struct sk_buff *skb)
{
	struct skb_shared_info *si;
	struct skb_config *cfg;
	struct net_device *dev;
	u32 key = 0;

	cfg = bpf_map_lookup_elem(&skb_config_map, &key);
	if (!cfg)
		return 0;

	return process_skb_l2_l4(ctx, event, cfg, skb);
}

DEFINE_HOOK(
	struct sk_buff *skb;

	skb = trace_get_sk_buff(ctx);
	if (skb)
		process_skb(ctx, event, skb);

	return 0;
)

char __license[] SEC("license") = "GPL";
