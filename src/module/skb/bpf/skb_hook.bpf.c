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
#define COLLECT_IPV4		1
#define COLLECT_IPV6		2
#define COLLECT_TCP		3
#define COLLECT_UDP		4
#define COLLECT_ICMP		5
#define COLLECT_DEV		6
#define COLLECT_NS		7
#define COLLECT_DATA_REF	8

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
struct skb_ipv4_event {
	u32 src;
	u32 dst;
	u16 len;
	u8 protocol;
} __attribute__((packed));
struct skb_ipv6_event {
	u128 src;
	u128 dst;
	u16 len;
	u8 protocol;
} __attribute__((packed));
struct skb_tcp_event {
	u16 sport;
	u16 dport;
	u32 seq;
	u32 ack_seq;
	u16 window;
	/* TCP flags: fin, syn, rst, psh, ack, urg, ece, cwr. */
	u8 flags;
	u8 doff;
} __attribute__((packed));
struct skb_udp_event {
	u16 sport;
	u16 dport;
	u16 len;
} __attribute__((packed));
struct skb_icmp_event {
	u8 type;
	u8 code;
} __attribute__((packed));
struct skb_netdev_event {
#define IFNAMSIZ	16
	u8 dev_name[IFNAMSIZ];
	u32 ifindex;
	u32 iif;
} __attribute__((packed));
struct skb_netns_event {
	u32 netns;
} __attribute__((packed));
struct skb_data_ref_event {
	u8 cloned;
	u8 fclone;
	u8 users;
	u8 dataref;
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

	/* L3 */

	/* We only support IPv4/IPv6. */
	if (etype != bpf_ntohs(0x800) && etype != bpf_ntohs(0x86dd))
		return 0;

	network = BPF_CORE_READ(skb, network_header);
	if (!network || network == mac || network == (u16)~0U)
		return 0;

	bpf_probe_read_kernel(&ip_version, sizeof(ip_version), head + network);
	ip_version >>= 4;

	if (ip_version == 4) {
		struct iphdr *ip4 = (struct iphdr *)(head + network);

		bpf_probe_read_kernel(&protocol, sizeof(protocol), &ip4->protocol);

		if (cfg->sections & BIT(COLLECT_IPV4)) {
			struct skb_ipv4_event *e =
				get_event_section(event, COLLECTOR_SKB,
						  COLLECT_IPV4, sizeof(*e));
			if (!e)
				return 0;

			e->protocol = protocol;
			bpf_probe_read_kernel(&e->src, sizeof(e->src), &ip4->saddr);
			bpf_probe_read_kernel(&e->dst, sizeof(e->dst), &ip4->daddr);
			bpf_probe_read_kernel(&e->len, sizeof(e->len), &ip4->tot_len);
		}
	} else if (ip_version == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *)(head + network);

		bpf_probe_read_kernel(&protocol, sizeof(protocol), &ip6->nexthdr);

		if (cfg->sections & BIT(COLLECT_IPV6)) {
			struct skb_ipv6_event *e =
				get_event_section(event, COLLECTOR_SKB,
						  COLLECT_IPV6, sizeof(*e));
			if (!e)
				return 0;

			e->protocol = protocol;
			bpf_probe_read_kernel(&e->src, sizeof(e->src), &ip6->saddr);
			bpf_probe_read_kernel(&e->dst, sizeof(e->dst), &ip6->daddr);
			bpf_probe_read_kernel(&e->len, sizeof(e->len), &ip6->payload_len);
		}
	} else {
		return 0;
	}

	/* L4 */

	transport = BPF_CORE_READ(skb, transport_header);
	if (!transport || transport == mac || transport == network ||
	    transport == (u16)~0U)
		return 0;

	if (protocol == IPPROTO_TCP && cfg->sections & BIT(COLLECT_TCP)) {
		struct tcphdr *tcp = (struct tcphdr *)(head + transport);
		struct skb_tcp_event *e =
			get_event_section(event, COLLECTOR_SKB, COLLECT_TCP,
					  sizeof(*e));
		if (!e)
			return 0;

		bpf_probe_read_kernel(&e->sport, sizeof(e->sport), &tcp->source);
		bpf_probe_read_kernel(&e->dport, sizeof(e->dport), &tcp->dest);
		bpf_probe_read_kernel(&e->seq, sizeof(e->seq), &tcp->seq);
		bpf_probe_read_kernel(&e->ack_seq, sizeof(e->ack_seq), &tcp->ack_seq);
		bpf_probe_read_kernel(&e->window, sizeof(e->window), &tcp->window);

		e->flags = (u8)BPF_CORE_READ_BITFIELD_PROBED(tcp, fin);
		e->flags |= (u8)BPF_CORE_READ_BITFIELD_PROBED(tcp, syn) << 1;
		e->flags |= (u8)BPF_CORE_READ_BITFIELD_PROBED(tcp, rst) << 2;
		e->flags |= (u8)BPF_CORE_READ_BITFIELD_PROBED(tcp, psh) << 3;
		e->flags |= (u8)BPF_CORE_READ_BITFIELD_PROBED(tcp, ack) << 4;
		e->flags |= (u8)BPF_CORE_READ_BITFIELD_PROBED(tcp, urg) << 5;
		e->flags |= (u8)BPF_CORE_READ_BITFIELD_PROBED(tcp, ece) << 6;
		e->flags |= (u8)BPF_CORE_READ_BITFIELD_PROBED(tcp, cwr) << 7;

		e->doff = (u8)BPF_CORE_READ_BITFIELD_PROBED(tcp, doff);
	} else if (protocol == IPPROTO_UDP && cfg->sections & BIT(COLLECT_UDP)) {
		struct udphdr *udp = (struct udphdr *)(head + transport);
		struct skb_udp_event *e =
			get_event_section(event, COLLECTOR_SKB, COLLECT_UDP,
					  sizeof(*e));
		if (!e)
			return 0;

		bpf_probe_read_kernel(&e->sport, sizeof(e->sport), &udp->source);
		bpf_probe_read_kernel(&e->dport, sizeof(e->dport), &udp->dest);
		bpf_probe_read_kernel(&e->len, sizeof(e->len), &udp->len);
	} else if (protocol == IPPROTO_ICMP && cfg->sections & BIT(COLLECT_ICMP)) {
		struct icmphdr *icmp = (struct icmphdr *)(head + transport);
		struct skb_icmp_event *e =
			get_event_section(event, COLLECTOR_SKB, COLLECT_ICMP,
					  sizeof(*e));
		if (!e)
			return 0;

		bpf_probe_read_kernel(&e->type, sizeof(e->type), &icmp->type);
		bpf_probe_read_kernel(&e->code, sizeof(e->code), &icmp->code);
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

	dev = BPF_CORE_READ(skb, dev);

	if (cfg->sections & BIT(COLLECT_DEV) && dev) {
		struct skb_netdev_event *e =
			get_event_section(event, COLLECTOR_SKB, COLLECT_DEV,
					  sizeof(*e));
		if (!e)
			return 0;

		bpf_probe_read(e->dev_name, IFNAMSIZ, dev->name);
		e->ifindex = BPF_CORE_READ(dev, ifindex);
		e->iif = BPF_CORE_READ(skb, skb_iif);
	}

	if (cfg->sections & BIT(COLLECT_NS)) {
		struct skb_netns_event *e;
		u32 netns;

		/* If the network device is initialized in the skb, use it to
		 * get the network namespace; otherwise try getting the network
		 * namespace from the skb associated socket.
		 */
		if (dev) {
			netns = BPF_CORE_READ(dev, nd_net.net, ns.inum);
		} else {
			struct sock *sk = BPF_CORE_READ(skb, sk);

			if (!sk)
				goto skip_netns;

			netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
		}

		e = get_event_section(event, COLLECTOR_SKB, COLLECT_NS, sizeof(*e));
		if (!e)
			return 0;

		e->netns = netns;
	}

skip_netns:
	if (cfg->sections & BIT(COLLECT_DATA_REF)) {
		unsigned char *head;
		struct skb_data_ref_event *e =
			get_event_section(event, COLLECTOR_SKB,
					  COLLECT_DATA_REF, sizeof(*e));
		if (!e)
			return 0;

		e->cloned = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, cloned);
		e->fclone = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, fclone);
		e->users = (u8)BPF_CORE_READ(skb, users.refs.counter);

		head = BPF_CORE_READ(skb, head);
		si = (struct skb_shared_info *)(BPF_CORE_READ(skb, end) + head);
		e->dataref = (u8)BPF_CORE_READ(si, dataref.counter);
	}

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
