#ifndef __MODULE_SKB_BPF_IF_VLAN__
#define __MODULE_SKB_BPF_IF_VLAN__

/* Code to handle VLAN tags ported from source/include/linux/if_vlan.h and
   modified to handle BPF */

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>
#include <compat.h>

#define	ENODATA		61
#define ETH_P_8021Q	0x8100
#define ETH_P_8021AD	0x88A8

// Used for kernels prior to 0c4b2d370514cb4f3454dd3b18f031d2651fab73.
#define VLAN_CFI_MASK		0x1000 /* Canonical Format Indicator */
#define VLAN_TAG_PRESENT	VLAN_CFI_MASK

#define set_skb_vlan_event(e, vlan_tci, vlan_accel)	{ \
	e->pcp = (vlan_tci & 0xe000) >> 13; \
	e->dei = (vlan_tci & 0x1000) >> 12; \
	e->vid = vlan_tci & 0x0fff; \
	e->acceleration = vlan_accel; \
}

struct skb_vlan_event {
	u8 pcp;
	u8 dei;
	u16 vid;
	u8 acceleration;
} __binding;

/**
 * vlan_tag_present tries to determine if a VLAN tag is present. There have been
 * various changes over the years in the kernel: The kernel uses
 * skb_vlan_tag_present which in more recent versions either relies on
 * vlan_present or on vlan_all.
 * We use CO-RE functionality to probe if either field is present and return
 * false otherwise.
 * See kernel commit 354259fa73e2
 *
 * @param skb
 *
 * Returns true if a VLAN tag is present in vlan_present or vlan_all
 */
static __always_inline bool vlan_tag_present(const struct sk_buff *skb)
{
	struct sk_buff___6_1_0 *skb_61 = (struct sk_buff___6_1_0 *)skb;

	// Older kernerls, e.g. RHEL 9.
	if (bpf_core_field_exists(skb_61->vlan_present))
		return BPF_CORE_READ_BITFIELD_PROBED(skb_61, vlan_present);

	// New kernels, e.g. Fedora 40 and later.
	if (bpf_core_field_exists(skb->vlan_all))
		return BPF_CORE_READ(skb, vlan_all);

	return false;
}

/**
 * vlan_tag_present_old implements logic from before kernel commit 0c4b2d370514
 * to determine if a VLAN tag is present. In old kernel versions,
 * __vlan_hwaccel_put_tag set skb->vlan_tci = VLAN_TAG_PRESENT | vlan_tci.
 * Therefore, old versions of the kernel use the DEI / CFI bit indicate / detect
 * presence of the VLAN tag.
 *
 * @param skb
 *
 * Returns true if a VLAN tag is present
 */
static __always_inline bool vlan_tag_present_old(const struct sk_buff *skb) {
	return (BPF_CORE_READ(skb, vlan_tci) & VLAN_TAG_PRESENT);
}

/**
 * __vlan_hwaccel_get_tag - get the VLAN TCI that is in @skb->cb[]. In newer
 * versions of the kernel, report the vlan_tci as is. Versions of the kernel
 * before commit 0c4b2d370514 always set the DEI / CFI bit to on. As it is more
 * common to have this bit off, and in order to not report a false positive, set
 * the bit to 0 for these old kernels.
 *
 * @skb: skbuff to query
 * @vlan_tci: buffer to store value
 *
 * Returns error if @skb->vlan_tci is not set correctly
 */
static inline int __vlan_hwaccel_get_tag(const struct sk_buff *skb,
					 u16 *vlan_tci)
{
	if (vlan_tag_present(skb)) {
		*vlan_tci = BPF_CORE_READ(skb, vlan_tci);
		return 0;
	} else if (vlan_tag_present_old(skb)) {
		*vlan_tci = BPF_CORE_READ(skb, vlan_tci) & 0xefff;
		return 0;
	} else {
		*vlan_tci = 0;
		return -ENODATA;
	}
}

/**
 * eth_type_vlan - check for valid vlan ether type.
 * @ethertype: ether type to check
 *
 * Returns true if the ether type is a vlan ether type.
 */
static inline bool eth_type_vlan(__be16 ethertype)
{
	switch (ethertype) {
	case bpf_htons(ETH_P_8021Q):
	case bpf_htons(ETH_P_8021AD):
		return true;
	default:
		return false;
	}
}

static inline struct vlan_ethhdr *skb_vlan_eth_hdr(const struct sk_buff *skb)
{
	if (is_mac_data_valid(skb)) {
		unsigned char *head = BPF_CORE_READ(skb, head);
		int mac = BPF_CORE_READ(skb, mac_header);
		return (struct vlan_ethhdr *)(head + mac);
	}

	return (struct vlan_ethhdr *) BPF_CORE_READ(skb, data);
}

/**
 * __vlan_get_tag - get the VLAN ID that is part of the payload
 * @skb: skbuff to query
 * @vlan_tci: buffer to store value
 *
 * Returns error if the skb is not of VLAN type
 */
static inline int __vlan_get_tag(const struct sk_buff *skb, u16 *vlan_tci)
{
	struct vlan_ethhdr *veth = skb_vlan_eth_hdr(skb);
	u16 h_vlan_proto;
	u16 h_vlan_TCI;

	bpf_probe_read_kernel(&h_vlan_proto, sizeof(__be16), &veth->h_vlan_proto);
	if (!eth_type_vlan(h_vlan_proto))
		return -ENODATA;

	bpf_probe_read_kernel(&h_vlan_TCI, sizeof(__be16), &veth->h_vlan_TCI);
	*vlan_tci = bpf_ntohs(h_vlan_TCI);
	return 0;
}

#endif /* __MODULE_SKB_BPF_IF_VLAN__ */
