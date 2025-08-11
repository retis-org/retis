#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

struct netns_event {
	u64 cookie;
	u32 inum;
} __binding;

static __always_inline struct net *get_net_from_parms(struct retis_context *ctx)
{
	struct net *net = retis_get_net(ctx);
	struct net_device *dev;

	if (net)
		return net;

	dev = retis_get_net_device(ctx);
	if (dev)
		return BPF_CORE_READ(dev, nd_net.net);

	return NULL;
}

static __always_inline struct net *get_net_from_skb(struct sk_buff *skb)
{
	struct net_device *dev = BPF_CORE_READ(skb, dev);
	struct sock *sk;

	if (dev)
		return BPF_CORE_READ(dev, nd_net.net);

	sk = BPF_CORE_READ(skb, sk);
	if (sk)
		return BPF_CORE_READ(sk, __sk_common.skc_net.net);

	return NULL;
}

DEFINE_HOOK_RAW(
	/* Netns cookies are not available on older kernels. */
	bool get_cookie = bpf_core_field_exists(struct net, net_cookie);
	struct netns_event *e;
	struct sk_buff *skb;
	struct net *net;
	u64 cookie;
	u32 inum;

	skb = retis_get_sk_buff(ctx);
	if (!skb || !skb_is_tracked(skb))
		return 0;

	net = get_net_from_skb(skb);
	if (!net) {
		/* Fallback to parameters. */
		net = get_net_from_parms(ctx);
		if (!net)
			return 0;
	}

	if (get_cookie)
		cookie = BPF_CORE_READ(net, net_cookie);
	inum = BPF_CORE_READ(net, ns.inum);

	e = get_event_section(event, COLLECTOR_NS, 0, sizeof(*e));
	if (!e)
		return 0;

	e->cookie = cookie;
	e->inum = inum;

	return 0;
)

char __license[] SEC("license") = "GPL";
