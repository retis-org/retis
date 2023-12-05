#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

#define BIT(x) (1 << (x))
#define min(a, b) ((a) < (b) ? (a) : (b))

#define ETH_P_IP	0x0800
#define ETH_P_ARP	0x0806
#define ETH_P_IPV6	0x86dd

/* Skb raw event sections.
 *
 * Please keep in sync with its Rust counterpart in module::skb::bpf.
 */
#define COLLECT_ETH		0
#define COLLECT_ARP		1
#define COLLECT_IPV4		2
#define COLLECT_IPV6		3
#define COLLECT_TCP		4
#define COLLECT_UDP		5
#define COLLECT_ICMP		6
#define COLLECT_DEV		7
#define COLLECT_NS		8
#define COLLECT_META		9
#define COLLECT_DATA_REF	10
#define COLLECT_PACKET		11

/* Skb hook configuration. A map is used to set the config from userspace.
 *
 * Please keep in sync with its Rust counterpart in module::skb::bpf.
 */
struct skb_config {
	u64 sections;
};
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
};
struct skb_arp_event {
	u16 operation;
	u8 sha[6];
	u32 spa;
	u8 tha[6];
	u32 tpa;
};
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
};
struct skb_ipv6_event {
	u128 src;
	u128 dst;
	u32 flow_lbl;
	u16 len;
	u8 protocol;
	u8 ttl;
	u8 ecn;
};
struct skb_tcp_event {
	u16 sport;
	u16 dport;
	u32 seq;
	u32 ack_seq;
	u16 window;
	/* TCP flags: fin, syn, rst, psh, ack, urg, ece, cwr. */
	u8 flags;
	u8 doff;
};
struct skb_udp_event {
	u16 sport;
	u16 dport;
	u16 len;
};
struct skb_icmp_event {
	u8 type;
	u8 code;
};
struct skb_netdev_event {
#define IFNAMSIZ	16
	u8 dev_name[IFNAMSIZ];
	u32 ifindex;
	u32 iif;
};
struct skb_netns_event {
	u32 netns;
};
struct skb_meta_event {
	u32 len;
	u32 data_len;
	u32 hash;
	u32 csum;
	u32 priority;
};
struct skb_data_ref_event {
	u8 nohdr;
	u8 cloned;
	u8 fclone;
	u8 users;
	u8 dataref;
};
/* Please keep the following structs in sync with its Rust counterpart in
 * module::skb::event.
 */
struct skb_packet_event {
	u32 len;
	u32 capture_len;
#define PACKET_CAPTURE_SIZE	256
	u8 packet[PACKET_CAPTURE_SIZE];
};

/* Must be called with a valid skb pointer */
static __always_inline int process_skb_arp(struct retis_raw_event *event,
					   struct skb_config *cfg,
					   struct sk_buff *skb,
					   unsigned char *head,
					   u16 mac, u16 network)
{
	struct skb_arp_event *e;
	struct arphdr *arp;
	unsigned char *ptr;

	if (!(cfg->sections & BIT(COLLECT_ARP)))
		return 0;

	arp = (struct arphdr *)(head + network);

#define ARPHRD_ETHER	1
	/* We only support ARP for IPv4 over Ethernet */
	if (BPF_CORE_READ(arp, ar_hrd) != bpf_htons(ARPHRD_ETHER) ||
	    BPF_CORE_READ(arp, ar_pro) != bpf_htons(ETH_P_IP))
		return 0;

#define ARPOP_REQUEST	1
#define ARPOP_REPLY	2
	/* We only support ARP request & reply */
	if (BPF_CORE_READ(arp, ar_op) != bpf_htons(ARPOP_REQUEST) &&
	    BPF_CORE_READ(arp, ar_op) != bpf_htons(ARPOP_REPLY))
		return 0;

	/* h/w addr len must be 6 (MAC) & protocol addr len 4 (IP) */
	if (BPF_CORE_READ(arp, ar_hln) != 6 || BPF_CORE_READ(arp, ar_pln) != 4)
		return 0;

	e = get_event_section(event, COLLECTOR_SKB, COLLECT_ARP, sizeof(*e));
	if (!e)
		return 0;

	bpf_probe_read_kernel(&e->operation, sizeof(e->operation), &arp->ar_op);

	/* Sender hardware address */
	ptr = (unsigned char *)(arp + 1);
	bpf_probe_read_kernel(&e->sha, sizeof(e->sha), ptr);

	/* Sender protocol address */
	ptr += 6; /* h/w addr len */
	bpf_probe_read_kernel(&e->spa, sizeof(e->spa), ptr);

	/* Target hardware address */
	ptr += 4; /* protocol addr len */
	bpf_probe_read_kernel(&e->tha, sizeof(e->tha), ptr);

	/* Target protocol address */
	ptr += 6; /* h/w addr len */
	bpf_probe_read_kernel(&e->tpa, sizeof(e->tpa), ptr);

	return 0;
}

/* Must be called with a valid skb pointer */
static __always_inline int process_skb_ip(struct retis_raw_event *event,
					  struct skb_config *cfg,
					  struct sk_buff *skb,
					  unsigned char *head,
					  u16 mac, u16 network)
{
	u8 protocol, ip_version;
	u16 transport;

	bpf_probe_read_kernel(&ip_version, sizeof(ip_version), head + network);
	ip_version >>= 4;

	if (ip_version == 4) {
		struct iphdr *ip4 = (struct iphdr *)(head + network);

		bpf_probe_read_kernel(&protocol, sizeof(protocol), &ip4->protocol);

		if (cfg->sections & BIT(COLLECT_IPV4)) {
			u16 frag_off;
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

			bpf_probe_read_kernel(&ecn, sizeof(ecn), ip6);
			e->ecn = (bpf_ntohs(ecn) >> 4) & 0x3;
		}
	} else {
		return 0;
	}

	/* L4 */

	transport = BPF_CORE_READ(skb, transport_header);
	if (!is_transport_data_valid(skb))
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
static __always_inline int process_skb_l2(struct retis_raw_event *event,
					  struct skb_config *cfg,
					  struct sk_buff *skb,
					  unsigned char *head)
{
	u16 mac, network, etype;

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

		if (is_mac_data_valid(skb)) {
			struct ethhdr *eth = (struct ethhdr *)(head + mac);

			bpf_probe_read_kernel(e->src, sizeof(e->src), eth->h_source);
			bpf_probe_read_kernel(e->dst, sizeof(e->dst), eth->h_dest);
		}

		e->etype = etype;
	}

	network = BPF_CORE_READ(skb, network_header);
	if (!is_network_data_valid(skb))
		return 0;

	/* IPv4/IPv6 and upper layers */
	if (etype == bpf_ntohs(ETH_P_IP) || etype == bpf_ntohs(ETH_P_IPV6))
		return process_skb_ip(event, cfg, skb, head, mac, network);
	/* ARP */
	else if (etype == bpf_ntohs(ETH_P_ARP))
		return process_skb_arp(event, cfg, skb, head, mac, network);

	/* Unsupported etype */
	return 0;
}

static __always_inline int process_packet(struct retis_raw_event *event,
					  struct sk_buff *skb)
{
	u32 len, linear_len, headroom;
	unsigned char *head, *data;
	struct skb_packet_event *e;
	u16 mac, network;
	/* Due to verifier issues on some (old) kernel versions, namely
	 * 5.15.0-88-generic on Ubuntu 22.04, size is limited to 0xff when
	 * retrieving packets starting at the mac offset and to 0xef for packets
	 * starting at the network offset. The difference in mask is due to the
	 * fake eth header added in the later case.
	 */
	int size;

	head = BPF_CORE_READ(skb, head);
	headroom = BPF_CORE_READ(skb, data) - head;

	mac = BPF_CORE_READ(skb, mac_header);
	network = BPF_CORE_READ(skb, network_header);
	len = BPF_CORE_READ(skb, len);
	linear_len = len - BPF_CORE_READ(skb, data_len); /* Linear buffer size */

	/* Best case: mac offset is set and valid */
	if (is_mac_data_valid(skb)) {
		int mac_offset;

		mac_offset = mac - headroom;
		size = min(linear_len - mac_offset, PACKET_CAPTURE_SIZE);
		if (size <= 0)
			return 0;

		e = get_event_section(event, COLLECTOR_SKB, COLLECT_PACKET,
				      sizeof(*e));
		if (!e)
			return 0;

		e->len = len - mac_offset;
		e->capture_len = size & 0xff;
		bpf_probe_read_kernel(e->packet, size & 0xff, head + mac);
	/* Valid network offset with an unset or invalid mac offset: we can fake
	 * the eth header.
	 */
	} else if (is_network_data_valid(skb)) {
		u16 etype = BPF_CORE_READ(skb, protocol);
		struct ethhdr *eth;
		int network_offset;

		/* We do need the ethertype to be set at the skb level here,
		 * otherwise we can't guess what kind of packet this is.
		 */
		if (!etype)
			return 0;

		network_offset = network - headroom;
		size = min(linear_len - network_offset, PACKET_CAPTURE_SIZE);
		size -= sizeof(struct ethhdr);
		if (size <= 0)
			return 0;

		e = get_event_section(event, COLLECTOR_SKB, COLLECT_PACKET,
				      sizeof(*e));
		if (!e)
			return 0;

		/* Fake eth header */
		eth = (struct ethhdr *)e->packet;
		__builtin_memset(eth, 0, sizeof(*eth));
		eth->h_proto = etype;

		e->len = len - network_offset + sizeof(*eth);
		e->capture_len = size & 0xef;
		bpf_probe_read_kernel(e->packet + sizeof(*eth), size & 0xef,
				      head + network);
	/* Can't guess any useful packet offset */
	} else {
		return 0;
	}

	return 0;
}

/* Must be called with a valid skb pointer */
static __always_inline int process_skb(struct retis_raw_event *event,
				       struct sk_buff *skb)
{
	struct skb_shared_info *si;
	struct skb_config *cfg;
	struct net_device *dev;
	unsigned char *head;
	u32 key = 0;

	cfg = bpf_map_lookup_elem(&skb_config_map, &key);
	if (!cfg)
		return 0;

	dev = BPF_CORE_READ(skb, dev);
	head = BPF_CORE_READ(skb, head);

	if (cfg->sections & BIT(COLLECT_PACKET))
		process_packet(event, skb);

	if (cfg->sections & BIT(COLLECT_DEV) && dev) {
		int ifindex = BPF_CORE_READ(dev, ifindex);

		if (ifindex > 0) {
			struct skb_netdev_event *e =
				get_event_section(event, COLLECTOR_SKB,
						  COLLECT_DEV, sizeof(*e));
			if (!e)
				return 0;

			bpf_probe_read(e->dev_name, IFNAMSIZ, dev->name);
			e->ifindex = ifindex;
			e->iif = BPF_CORE_READ(skb, skb_iif);
		}
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
		struct skb_data_ref_event *e =
			get_event_section(event, COLLECTOR_SKB,
					  COLLECT_DATA_REF, sizeof(*e));
		if (!e)
			return 0;

		e->nohdr = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, nohdr);
		e->cloned = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, cloned);
		e->fclone = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, fclone);
		e->users = (u8)BPF_CORE_READ(skb, users.refs.counter);

		si = (struct skb_shared_info *)(BPF_CORE_READ(skb, end) + head);
		e->dataref = (u8)BPF_CORE_READ(si, dataref.counter);
	}

	return process_skb_l2(event, cfg, skb, head);
}

DEFINE_HOOK(F_AND, RETIS_F_PACKET_PASS,
	struct sk_buff *skb;

	skb = retis_get_sk_buff(ctx);
	if (skb)
		process_skb(event, skb);

	return 0;
)

char __license[] SEC("license") = "GPL";
