#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

BINDING_DEF(IFNAMSIZ, 16)

struct dev_event {
	u8 dev_name[IFNAMSIZ];
	u32 ifindex;
	u32 iif;
} __binding;

DEFINE_HOOK(
	struct sk_buff *skb;
	struct net_device *dev;
	struct dev_event *e;
	int ifindex;

	skb = retis_get_sk_buff(ctx);
	dev = skb ? BPF_CORE_READ(skb, dev) : retis_get_net_device(ctx);
	if (!dev)
		return 0;

	ifindex = BPF_CORE_READ(dev, ifindex);
	if (!ifindex)
		return 0;

	e = get_event_section(event, COLLECTOR_DEV, 1, sizeof(*e));
	if (!e)
		return 0;

	bpf_probe_read(e->dev_name, IFNAMSIZ, dev->name);
	e->ifindex = ifindex;

	if (skb)
		e->iif = BPF_CORE_READ(skb, skb_iif);

	return 0;
)

char __license[] SEC("license") = "GPL";
