#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

struct netns_event {
	u64 cookie;
	u32 inum;
} __binding;

DEFINE_HOOK_RAW(
	/* Netns cookies are not available on older kernels. */
	bool get_cookie = bpf_core_field_exists(struct net, net_cookie);
	struct netns_event *e;
	struct net *net;
	u64 cookie;
	u32 inum;

	net = retis_get_net(ctx);
	if (!net) {
		struct net_device *dev;
		struct sk_buff *skb;

		skb = retis_get_sk_buff(ctx);
		if (!skb || !skb_is_tracked(skb))
			return 0;

		dev = BPF_CORE_READ(skb, dev);
		if (!dev)
			dev = retis_get_net_device(ctx);

		/* If the network device is initialized in the skb, use it to
		 * get the network namespace; otherwise try getting the network
		 * namespace from the skb associated socket.
		 */
		if (dev) {
			net = BPF_CORE_READ(dev, nd_net.net);
		} else {
			struct sock *sk = BPF_CORE_READ(skb, sk);

			if (!sk)
				return 0;

			net = BPF_CORE_READ(sk, __sk_common.skc_net.net);
		}
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
