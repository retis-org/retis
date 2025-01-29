#ifndef __MODULE_SKB_BPF_IF_VLAN__
#define __MODULE_SKB_BPF_IF_VLAN__

/* Code to handle VLAN tags ported from source/include/linux/if_vlan.h and modified to handle BPF */

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>
#include <compat.h>

#define	ENODATA		61

#define set_skb_vlan_event(e, vlan_tci)	{ \
	e->pcp = (vlan_tci & 0xe000) >> 13; \
	e->dei = (vlan_tci & 0x1000) >> 12; \
	e->vid = vlan_tci & 0x0fff; \
}

struct skb_vlan_event {
	u8 pcp;
	u8 dei;
	u16 vid;
} __binding;

static __always_inline bool vlan_tag_present(const struct sk_buff *skb)
{
       struct sk_buff___6_1_0 *skb_61 = (struct sk_buff___6_1_0 *)skb;

       if (bpf_core_field_exists(skb_61->vlan_present))
               return BPF_CORE_READ_BITFIELD_PROBED(skb_61, vlan_present);

       return BPF_CORE_READ(skb, vlan_all);
}

/**
 * __vlan_hwaccel_get_tag - get the VLAN ID that is in @skb->cb[]
 * The kernel uses skb_vlan_tag_present which either relies on vlan_present or
 * on vlan_all depending on the kernel version (see commit 354259fa73e2aac92ae5e19522adb69a92c15b49).
 * We use CO-RE functionality to probe either field in vlan_tag_present.
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
	} else {
		*vlan_tci = 0;
		return -ENODATA;
	}
}

#endif /* __MODULE_SKB_BPF_IF_VLAN__ */
