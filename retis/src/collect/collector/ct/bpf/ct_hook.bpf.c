#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

#include <common.h>

/* Please keep these in sync with
* include/linux/netfilter/nf_conntrack_common.h.
*/
#define NFCT_INFOMASK	7UL
#define NFCT_PTRMASK	~(NFCT_INFOMASK)

/* Keep in sync with include/linux/netfilter/nf_conntrack_zones_common.h */
#define NF_CT_ZONE_DIR_ORIG	(1 << IP_CT_DIR_ORIGINAL)
#define NF_CT_ZONE_DIR_REPL	(1 << IP_CT_DIR_REPLY)
#define NF_CT_DEFAULT_ZONE_DIR	(NF_CT_ZONE_DIR_ORIG | NF_CT_ZONE_DIR_REPL)

#define ORIG tuplehash[IP_CT_DIR_ORIGINAL].tuple
#define REPLY tuplehash[IP_CT_DIR_REPLY].tuple

enum ct_sections {
	SECTION_META = 0,
	SECTION_BASE_CONN,
	SECTION_PARENT_CONN,
} __binding;

/* Retis-specific flags */
enum ct_flags {
	RETIS_CT_DIR_ORIG	= 1 << 0,
	RETIS_CT_DIR_REPLY	= 1 << 1,
	RETIS_CT_IPV4		= 1 << 2,
	RETIS_CT_IPV6		= 1 << 3,
	RETIS_CT_PROTO_TCP	= 1 << 4,
	RETIS_CT_PROTO_UDP	= 1 << 5,
	RETIS_CT_PROTO_ICMP	= 1 << 6,
} __binding;

struct ct_meta_event {
	u8 state;
} __binding;

union nf_conn_ip {
	u32 ipv4;
	u8 ipv6[16];
} __binding;

struct nf_conn_addr_proto {
	union nf_conn_ip addr;
	/* per-protocol generic data */
	u16 data;
} __binding;

struct nf_conn_tuple {
	struct nf_conn_addr_proto src;
	struct nf_conn_addr_proto dst;
} __binding;

/* Conntrack event information */
struct ct_event {
	struct nf_conn_tuple orig;
	struct nf_conn_tuple reply;
	u64 status;
	u32 flags;
	u32 mark;
	u8 labels[16];
	u16 zone_id;
	u8 tcp_state;
} __binding;

static __always_inline bool ct_protocol_is_supported(u16 l3num, u8 protonum)
{
	switch (l3num) {
	case NFPROTO_IPV4:
	case NFPROTO_IPV6:
		break;
	default:
		return false;
	}

	switch (protonum) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
		break;
	default:
		return false;
	}

	return true;
}

/* See ctnetlink_dump_labels(). */
static __always_inline void get_nf_ct_labels(struct ct_event *e,
					     struct nf_conn *ct)
{
	struct nf_ct_ext *ext = BPF_CORE_READ(ct, ext);
	struct nf_conn_labels *labels;
	int offset, nf_ct_ext_labels;

	/* Conntrack labels depend on CONFIG_NF_CONNTRACK_LABELS, the following
	 * enum variant is only defined if enabled.
	 */
	if (!bpf_core_enum_value_exists(enum nf_ct_ext_id, NF_CT_EXT_LABELS))
		return;

	if (!ext)
		return;

	nf_ct_ext_labels = bpf_core_enum_value(enum nf_ct_ext_id, NF_CT_EXT_LABELS);
	offset = BPF_CORE_READ(ext, offset)[nf_ct_ext_labels];
	if (!offset)
		return;

	labels = (void *)ext + offset;

	BUILD_BUG_ON(sizeof(labels->bits) != sizeof(e->labels));
	bpf_core_read(&e->labels, sizeof(labels->bits), &labels->bits);
}

static __always_inline int process_nf_conn(struct ct_event *e,
					   struct nf_conn *ct, u16 l3num,
					   u8 protonum)
{
	u8 zone_dir;

	if (bpf_core_field_exists(ct->zone)) {
		zone_dir = (u8) BPF_CORE_READ(ct, zone.dir);
		if (zone_dir & NF_CT_ZONE_DIR_ORIG)
			e->flags |= RETIS_CT_DIR_ORIG;
		if (zone_dir & NF_CT_ZONE_DIR_REPL)
			e->flags |= RETIS_CT_DIR_REPLY;

		e->zone_id = (u16) BPF_CORE_READ(ct, zone.id);
	}

	if (bpf_core_field_exists(ct->mark))
		e->mark = BPF_CORE_READ(ct, mark);

	e->status = BPF_CORE_READ(ct, status);
	switch (l3num) {
	case NFPROTO_IPV4:
		e->flags |= RETIS_CT_IPV4;
		bpf_core_read(&e->orig.src.addr.ipv4,
			      sizeof(e->orig.src.addr.ipv4),
			      &ct->ORIG.src.u3.ip);
		bpf_core_read(&e->orig.dst.addr.ipv4,
			      sizeof(e->orig.dst.addr.ipv4),
			      &ct->ORIG.dst.u3.ip);
		bpf_core_read(&e->reply.src.addr.ipv4,
			      sizeof(e->reply.src.addr.ipv4),
			      &ct->REPLY.src.u3.ip);
		bpf_core_read(&e->reply.dst.addr.ipv4,
			      sizeof(e->reply.dst.addr.ipv4),
			      &ct->REPLY.dst.u3.ip);
		break;
	case NFPROTO_IPV6:
		e->flags |= RETIS_CT_IPV6;
		bpf_core_read(&e->orig.src.addr.ipv6,
			      sizeof(e->orig.src.addr.ipv6),
			      &ct->ORIG.src.u3.ip6);
		bpf_core_read(&e->orig.dst.addr.ipv6,
			      sizeof(e->orig.dst.addr.ipv6),
			      &ct->ORIG.dst.u3.ip6);
		bpf_core_read(&e->reply.src.addr.ipv6,
			      sizeof(e->reply.src.addr.ipv6),
			      &ct->REPLY.src.u3.ip6);
		bpf_core_read(&e->reply.dst.addr.ipv6,
			      sizeof(e->reply.dst.addr.ipv6),
			      &ct->REPLY.dst.u3.ip6);
		break;
	}

	switch (protonum) {
	case IPPROTO_TCP:
		e->flags |= RETIS_CT_PROTO_TCP;
		bpf_core_read(&e->orig.src.data, sizeof(e->orig.src.data),
			      &ct->ORIG.src.u.tcp.port);
		bpf_core_read(&e->orig.dst.data, sizeof(e->orig.dst.data),
			      &ct->ORIG.dst.u.tcp.port);
		bpf_core_read(&e->reply.src.data, sizeof(e->reply.src.data),
			      &ct->REPLY.src.u.tcp.port);
		bpf_core_read(&e->reply.dst.data, sizeof(e->reply.dst.data),
			      &ct->REPLY.dst.u.tcp.port);

		e->tcp_state = (u8)BPF_CORE_READ(ct, proto.tcp.state);

		break;
	case IPPROTO_UDP:
		e->flags |= RETIS_CT_PROTO_UDP;
		bpf_core_read(&e->orig.src.data, sizeof(e->orig.src.data),
			      &ct->ORIG.src.u.udp.port);
		bpf_core_read(&e->orig.dst.data, sizeof(e->orig.dst.data),
			      &ct->ORIG.dst.u.udp.port);
		bpf_core_read(&e->reply.src.data, sizeof(e->reply.src.data),
			      &ct->REPLY.src.u.udp.port);
		bpf_core_read(&e->reply.dst.data, sizeof(e->reply.dst.data),
			      &ct->REPLY.dst.u.udp.port);
		break;
	case IPPROTO_ICMP:
		e->flags |= RETIS_CT_PROTO_ICMP;
		/* Source contains u16 id. Destination contains code and type,
		 * both u8 so we fit them into the single u16 field.
		 */
		bpf_core_read(&e->orig.src.data, sizeof(e->orig.src.data),
			      &ct->ORIG.src.u.icmp.id);
		e->orig.dst.data =
			((u8) BPF_CORE_READ(ct, ORIG.dst.u.icmp.type) << 8) |
			(u8) BPF_CORE_READ(ct, ORIG.dst.u.icmp.code);

		bpf_core_read(&e->reply.src.data, sizeof(e->reply.src.data),
			      &ct->REPLY.src.u.icmp.id);
		e->reply.dst.data =
			((u8) BPF_CORE_READ(ct, REPLY.dst.u.icmp.type) << 8) |
			(u8) BPF_CORE_READ(ct, REPLY.dst.u.icmp.code);
		break;
	}

	get_nf_ct_labels(e, ct);

	return 0;
}

DEFINE_HOOK(F_AND, RETIS_ALL_FILTERS,
	struct nf_conn *nf_conn;
	struct ct_meta_event *m;
	struct sk_buff *skb;
	unsigned long nfct;
	struct ct_event *e;
	u8 protonum;
	u16 l3num;

	skb = retis_get_sk_buff(ctx);
	if (!skb)
		return 0;

	if (!bpf_core_field_exists(skb->_nfct))
		return 0;

	nfct = (unsigned long) BPF_CORE_READ(skb, _nfct);
	if (!nfct)
		return 0;

	nf_conn = (struct nf_conn *)(nfct & NFCT_PTRMASK);
	if (!nf_conn)
		return 0;

	l3num = (u16) BPF_CORE_READ(nf_conn, ORIG.src.l3num);
	protonum = (u8) BPF_CORE_READ(nf_conn, ORIG.dst.protonum);

	if (!ct_protocol_is_supported(l3num, protonum))
		return 0;

	e = get_event_zsection(event, COLLECTOR_CT, SECTION_BASE_CONN,
			       sizeof(*e));
	if (!e)
		return 0;
	process_nf_conn(e, nf_conn, l3num, protonum);

	nf_conn = BPF_CORE_READ(nf_conn, master);
	if (nf_conn) {
		e = get_event_zsection(event, COLLECTOR_CT, SECTION_PARENT_CONN,
				       sizeof(*e));
		if (!e)
			return 0;
		process_nf_conn(e, nf_conn,
				(u16)BPF_CORE_READ(nf_conn, ORIG.src.l3num),
				(u8)BPF_CORE_READ(nf_conn, ORIG.dst.protonum));

	}

	m = get_event_section(event, COLLECTOR_CT, SECTION_META, sizeof(*m));
	if (!m)
		return 0;
	m->state = (u8)(nfct & NFCT_INFOMASK);

	return 0;
)

char __license[] SEC("license") = "GPL";
