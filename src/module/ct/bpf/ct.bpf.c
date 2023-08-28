#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

#include <common.h>

/* Retis-specific flags */
#define RETIS_CT_DIR_ORIG	1 << 0
#define RETIS_CT_DIR_REPLY	1 << 1

/* Please keep these in sync with
* include/linux/netfilter/nf_conntrack_common.h.
*/
#define NFCT_INFOMASK	7UL
#define NFCT_PTRMASK	~(NFCT_INFOMASK)

/* Keep in sync with include/linux/netfilter/nf_conntrack_zones_common.h */
#define NF_CT_ZONE_DIR_ORIG	(1 << IP_CT_DIR_ORIGINAL)
#define NF_CT_ZONE_DIR_REPL	(1 << IP_CT_DIR_REPLY)
#define NF_CT_DEFAULT_ZONE_DIR	(NF_CT_ZONE_DIR_ORIG | NF_CT_ZONE_DIR_REPL)

/* Conntrack entry information */
struct ct_event {
	u32 flags;
	u16 zone_id;
} __attribute__((packed));

static __always_inline int process_nf_conn(struct retis_raw_event *event,
					   struct nf_conn *ct)
{
	struct nf_conntrack_zone *zone;
	struct nf_conn *nf_conn;
	struct ct_event *e;
	u8 zone_dir;

	e = get_event_section(event, COLLECTOR_CT, 0, sizeof(*e));
	if (!e)
		return 0;

	if (bpf_core_field_exists(ct->zone)) {
		zone_dir = (u8) BPF_CORE_READ(ct, zone.dir);
		if (zone_dir & NF_CT_ZONE_DIR_ORIG)
			e->flags |= RETIS_CT_DIR_ORIG;
		if (zone_dir & NF_CT_ZONE_DIR_REPL)
			e->flags |= RETIS_CT_DIR_REPLY;

		e->zone_id = (u8) BPF_CORE_READ(ct, zone.id);
	}

	return 0;
}

DEFINE_HOOK(F_AND, RETIS_F_PACKET_PASS,
	struct nf_conn *nf_conn;
	struct sk_buff *skb;
	unsigned long nfct;

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

	return process_nf_conn(event, nf_conn);
)

char __license[] SEC("license") = "GPL";
