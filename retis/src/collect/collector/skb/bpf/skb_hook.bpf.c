#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

#define BIT(x) (1 << (x))

#define ETH_P_IP	0x0800
#define ETH_P_ARP	0x0806
#define ETH_P_IPV6	0x86dd

/* Skb raw event sections. */
enum skb_sections {
	SECTION_PACKET = 1,
	SECTION_DEV,
	SECTION_NS,
	SECTION_META,
	SECTION_DATA_REF,
	SECTION_GSO,
} __binding;

/* Skb hook configuration. A map is used to set the config from
 * userspace.
 */
struct skb_config {
	u64 sections;
} __binding;
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct skb_config);
} skb_config_map SEC(".maps");

BINDING_DEF(IFNAMSIZ, 16)

struct skb_netdev_event {
	u8 dev_name[IFNAMSIZ];
	u32 ifindex;
	u32 iif;
} __binding;
struct skb_netns_event {
	u32 netns;
} __binding;
struct skb_meta_event {
	u32 len;
	u32 data_len;
	u32 hash;
	u8 ip_summed;
	u32 csum;
	u8 csum_level;
	u32 priority;
} __binding;
struct skb_data_ref_event {
	u8 nohdr;
	u8 cloned;
	u8 fclone;
	u8 users;
	u8 dataref;
} __binding;
struct skb_gso_event {
	u8 flags;
	u8 nr_frags;
	u32 gso_size;
	u32 gso_segs;
	u32 gso_type;
} __binding;
struct skb_packet_event {
	u32 len;
	u32 capture_len;
#define PACKET_CAPTURE_SIZE	255
	u8 packet[PACKET_CAPTURE_SIZE];
	u8 fake_eth;
} __binding;

/* Retrieve an skb linear len */
static __always_inline int skb_linear_len(struct sk_buff *skb)
{
	return BPF_CORE_READ(skb, len) - BPF_CORE_READ(skb, data_len);
}

/* Retrieve the L3 protocol of an skb, either by looking up skb->protocol or by
 * parsing the header of the packet.
 */
static __always_inline u16 skb_protocol(struct sk_buff *skb)
{
	u16 protocol = BPF_CORE_READ(skb, protocol);
	int network, transport, l4hlen;
	unsigned char *head;
	u8 ip_version;

	/* Fast path, skb->protocol was set. */
	if (likely(protocol))
		return protocol;

	/* We're *most likely* in the Tx path; skb->protocol wasn't set yet.
	 * Let's try to detect the protocol from the packet data.
	 */

	head = BPF_CORE_READ(skb, head);

	/* L4 must be set as we derive L3 header len from it. */
	if (!is_network_data_valid(skb) || !is_transport_data_valid(skb))
		return 0;

	network = BPF_CORE_READ(skb, network_header);
	transport = BPF_CORE_READ(skb, transport_header);
	l4hlen = transport - network;

	/* Check if the L3 header looks like an IP one. The below is not 100%
	 * right (no ext support), but let's stay on the safe side for now.
	 */
	bpf_probe_read_kernel(&ip_version, sizeof(ip_version), head + network);
	ip_version >>= 4;
	if (ip_version == 4 && l4hlen == sizeof(struct iphdr)) {
		return bpf_htons(ETH_P_IP);
	} else if (ip_version == 6 && l4hlen == sizeof(struct ipv6hdr)) {
		return bpf_htons(ETH_P_IPV6);
	}

	return 0;
}

static __always_inline int process_packet(struct retis_raw_event *event,
					  struct sk_buff *skb)
{
	/* Use int instead of the underlying (smaller) unsigned type to allow
	 * signed arithmetic operations.
	 */
	int mac, headroom, linear_len;
	struct skb_packet_event *e;
	unsigned char *head;
	u16 network;
	u32 len;

	head = BPF_CORE_READ(skb, head);
	headroom = BPF_CORE_READ(skb, data) - head;

	mac = BPF_CORE_READ(skb, mac_header);
	network = BPF_CORE_READ(skb, network_header);
	linear_len = skb_linear_len(skb);
	len = BPF_CORE_READ(skb, len);

	/* No data in the linear len, nothing to report */
	if (!linear_len)
		return 0;

	/* Best case: mac offset is set and valid */
	if (is_mac_data_valid(skb)) {
		long mac_offset, size;

		mac_offset = mac - headroom;
		size = MIN(linear_len - mac_offset, PACKET_CAPTURE_SIZE);
		if (size <= 0)
			return 0;

		e = get_event_section(event, COLLECTOR_SKB, SECTION_PACKET,
				      sizeof(*e));
		if (!e)
			return 0;

		e->len = len - mac_offset;
		e->capture_len = size;
		e->fake_eth = 0;
		bpf_probe_read_kernel(e->packet, size, head + mac);
	/* Valid network offset with an unset or invalid mac offset: we can fake
	 * the eth header.
	 */
	} else if (is_network_data_valid(skb)) {
		u16 etype = skb_protocol(skb);
		long network_offset, size;
		struct ethhdr *eth;

		/* We do need the ethertype to be set at the skb level here,
		 * otherwise we can't guess what kind of packet this is.
		 */
		if (!etype)
			return 0;

		network_offset = network - headroom;
		size = MIN(linear_len - network_offset,
			   PACKET_CAPTURE_SIZE - sizeof(struct ethhdr));
		if (size <= 0)
			return 0;

		e = get_event_section(event, COLLECTOR_SKB, SECTION_PACKET,
				      sizeof(*e));
		if (!e)
			return 0;

		/* Fake eth header */
		eth = (struct ethhdr *)e->packet;
		__builtin_memset(eth, 0, sizeof(*eth));
		eth->h_proto = etype;

		e->len = len - network_offset + sizeof(*eth);
		e->capture_len = size + sizeof(struct ethhdr);
		e->fake_eth = 1;
		bpf_probe_read_kernel(e->packet + sizeof(*eth), size,
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
	u32 key = 0;

	cfg = bpf_map_lookup_elem(&skb_config_map, &key);
	if (!cfg)
		return 0;

	dev = BPF_CORE_READ(skb, dev);

	/* Always retrieve the raw packet */
	process_packet(event, skb);

	if (cfg->sections & BIT(SECTION_DEV) && dev) {
		int ifindex = BPF_CORE_READ(dev, ifindex);

		if (ifindex > 0) {
			struct skb_netdev_event *e =
				get_event_section(event, COLLECTOR_SKB,
						  SECTION_DEV, sizeof(*e));
			if (!e)
				return 0;

			bpf_probe_read(e->dev_name, IFNAMSIZ, dev->name);
			e->ifindex = ifindex;
			e->iif = BPF_CORE_READ(skb, skb_iif);
		}
	}

	if (cfg->sections & BIT(SECTION_NS)) {
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

		e = get_event_section(event, COLLECTOR_SKB, SECTION_NS, sizeof(*e));
		if (!e)
			return 0;

		e->netns = netns;
	}

skip_netns:
	if (cfg->sections & BIT(SECTION_META)) {
		struct skb_meta_event *e =
			get_event_section(event, COLLECTOR_SKB,
					  SECTION_META, sizeof(*e));
		if (!e)
			return 0;

		e->len = BPF_CORE_READ(skb, len);
		e->data_len = BPF_CORE_READ(skb, data_len);
		e->hash = BPF_CORE_READ(skb, hash);
		e->ip_summed = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, ip_summed);
		e->csum = BPF_CORE_READ(skb, csum);
		e->csum_level = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, csum_level);
		e->priority = BPF_CORE_READ(skb, priority);
	}

	if (cfg->sections & BIT(SECTION_DATA_REF)) {
		unsigned char *head = BPF_CORE_READ(skb, head);
		struct skb_data_ref_event *e =
			get_event_section(event, COLLECTOR_SKB,
					  SECTION_DATA_REF, sizeof(*e));
		if (!e)
			return 0;

		e->nohdr = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, nohdr);
		e->cloned = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, cloned);
		e->fclone = (u8)BPF_CORE_READ_BITFIELD_PROBED(skb, fclone);
		e->users = (u8)BPF_CORE_READ(skb, users.refs.counter);

		si = (struct skb_shared_info *)(BPF_CORE_READ(skb, end) + head);
		e->dataref = (u8)BPF_CORE_READ(si, dataref.counter);
	}

	if (cfg->sections & BIT(SECTION_GSO)) {
		struct skb_shared_info *shinfo;
		struct skb_gso_event *e;

		/* See skb_shinfo */
		shinfo = (void *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, end));
		/* See skb_is_gso */
		if (!BPF_CORE_READ(shinfo, gso_size))
			goto skip_gso;

		e = get_event_section(event, COLLECTOR_SKB, SECTION_GSO,
				      sizeof(*e));
		if (!e)
			return 0;

		e->flags = bpf_core_field_exists(shinfo->flags) ?
			   BPF_CORE_READ(shinfo, flags) : 0;
		e->nr_frags = BPF_CORE_READ(shinfo, nr_frags);
		e->gso_size = BPF_CORE_READ(shinfo, gso_size);
		e->gso_segs = BPF_CORE_READ(shinfo, gso_segs);
		e->gso_type = BPF_CORE_READ(shinfo, gso_type);
	}

skip_gso:
	return 0;
}

DEFINE_HOOK(F_AND, RETIS_ALL_FILTERS,
	struct sk_buff *skb;

	skb = retis_get_sk_buff(ctx);
	if (skb)
		process_skb(event, skb);

	return 0;
)

char __license[] SEC("license") = "GPL";
