#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

#define BIT(x) (1 << (x))

/* Skb raw event sections.
 *
 * Please keep in sync with its Rust counterpart in module::skb::bpf.
 */
#define COLLECT_ETH		0
#define COLLECT_IPV4		1
#define COLLECT_IPV6		2
#define COLLECT_TCP		3
#define COLLECT_UDP		4
#define COLLECT_ICMP		5
#define COLLECT_DEV		6
#define COLLECT_NS		7
#define COLLECT_META		8
#define COLLECT_DATA_REF	9

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
	__type(value, struct skb_config);
} skb_config_map SEC(".maps");

/* Please keep the following structs in sync with its Rust counterpart in
 * module::skb::bpf.
 */
struct skb_eth_event {
	u8 dst[6];
	u8 src[6];
	u16 etype;
} __attribute__((packed));
struct skb_ipv4_event {
	u32 src;
	u32 dst;
	u16 len;
	u16 id;
	u8 protocol;
	u8 ttl;
	u8 tos;
	u8 ecn;
	u16 offset;
	u8 flags;
} __attribute__((packed));
struct skb_ipv6_event {
	u128 src;
	u128 dst;
	u32 flow_lbl;
	u16 len;
	u8 protocol;
	u8 ttl;
	u8 ecn;
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
struct skb_meta_event {
	u32 len;
	u32 data_len;
	u32 hash;
	u32 csum;
	u32 priority;
} __attribute__((packed));
struct skb_data_ref_event {
	u8 nohdr;
	u8 cloned;
	u8 fclone;
	u8 users;
	u8 dataref;
} __attribute__((packed));

/* Must be called with a valid skb pointer */
static __always_inline int process_skb_l2_l4(struct retis_context *ctx,
					     struct retis_raw_event *event,
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

	if (cfg->sections & BIT(COLLECT_ETH)) {
		struct skb_eth_event *e =
			get_event_zsection(event, COLLECTOR_SKB, COLLECT_ETH,
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
			u16 frag_off, offset;
			u8 tos;
			struct skb_ipv4_event *e =
				get_event_section(event, COLLECTOR_SKB,
						  COLLECT_IPV4, sizeof(*e));
			if (!e)
				return 0;

			e->protocol = protocol;
			bpf_probe_read_kernel(&e->src, sizeof(e->src), &ip4->saddr);
			bpf_probe_read_kernel(&e->dst, sizeof(e->dst), &ip4->daddr);
			bpf_probe_read_kernel(&e->len, sizeof(e->len), &ip4->tot_len);
			bpf_probe_read_kernel(&e->id, sizeof(e->id), &ip4->id);
			bpf_probe_read_kernel(&e->ttl, sizeof(e->ttl), &ip4->ttl);

			bpf_probe_read_kernel(&tos, sizeof(tos), &ip4->tos);
			e->ecn = tos & 0x3;
			e->tos = tos;

/* Keep in sync with Linux's include/net/ip.h */
#define IP_CE		0x8000
#define IP_DF		0x4000
#define IP_MF		0x2000
#define IP_OFFSET	0x1fff
			bpf_probe_read_kernel(&frag_off, sizeof(frag_off), &ip4->frag_off);
			e->flags = !!(frag_off & bpf_htons(IP_CE));
			e->flags |= !!(frag_off & bpf_htons(IP_DF)) << 1;
			e->flags |= !!(frag_off & bpf_htons(IP_MF)) << 2;

			e->offset = frag_off & bpf_htons(IP_OFFSET);

			/* We won't be able to parse upper layer if this is a
			 * fragment, bail out.
			 */
			if (e->offset > 0)
				return 0;
		}
	} else if (ip_version == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *)(head + network);

		bpf_probe_read_kernel(&protocol, sizeof(protocol), &ip6->nexthdr);

		if (cfg->sections & BIT(COLLECT_IPV6)) {
			u8 flow_lbl[3];
			u16 ecn;
			struct skb_ipv6_event *e =
				get_event_section(event, COLLECTOR_SKB,
						  COLLECT_IPV6, sizeof(*e));
			if (!e)
				return 0;

			e->protocol = protocol;
			bpf_probe_read_kernel(&e->src, sizeof(e->src), &ip6->saddr);
			bpf_probe_read_kernel(&e->dst, sizeof(e->dst), &ip6->daddr);
			bpf_probe_read_kernel(&e->len, sizeof(e->len), &ip6->payload_len);
			bpf_probe_read_kernel(&e->ttl, sizeof(e->ttl), &ip6->hop_limit);

			bpf_probe_read_kernel(&flow_lbl, sizeof(flow_lbl), &ip6->flow_lbl);
			e->flow_lbl = (flow_lbl[0] & 0xf) << 16 |
				      flow_lbl[1] << 8 | flow_lbl[2];
			e->flow_lbl &= 0xfffff;

			bpf_probe_read_kernel(&ecn, sizeof(ecn), &ip6);
			e->ecn = (bpf_ntohs(ecn) >> 4) & 0x3;
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
static __always_inline int process_skb(struct retis_context *ctx,
				       struct retis_raw_event *event,
				       struct sk_buff *skb)
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
	if (cfg->sections & BIT(COLLECT_META)) {
		struct skb_meta_event *e =
			get_event_section(event, COLLECTOR_SKB,
					  COLLECT_META, sizeof(*e));
		if (!e)
			return 0;

		e->len = BPF_CORE_READ(skb, len);
		e->data_len = BPF_CORE_READ(skb, data_len);
		e->hash = BPF_CORE_READ(skb, hash);
		e->csum = BPF_CORE_READ(skb, csum);
		e->priority = BPF_CORE_READ(skb, priority);
	}

	if (cfg->sections & BIT(COLLECT_DATA_REF)) {
		unsigned char *head;
		struct skb_data_ref_event *e =
			get_event_section(event, COLLECTOR_SKB,
					  COLLECT_DATA_REF, sizeof(*e));
		if (!e)
			return 0;

		e->nohdr = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, nohdr);
		e->cloned = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, cloned);
		e->fclone = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, fclone);
		e->users = (u8)BPF_CORE_READ(skb, users.refs.counter);

		head = BPF_CORE_READ(skb, head);
		si = (struct skb_shared_info *)(BPF_CORE_READ(skb, end) + head);
		e->dataref = (u8)BPF_CORE_READ(si, dataref.counter);
	}

	return process_skb_l2_l4(ctx, event, cfg, skb);
}

DEFINE_HOOK(F_AND, RETIS_F_PACKET_PASS,
	struct sk_buff *skb;

	skb = retis_get_sk_buff(ctx);
	if (skb)
		process_skb(ctx, event, skb);

	return 0;
)

char __license[] SEC("license") = "GPL";
