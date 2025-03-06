#ifndef __CORE_PROBE_KERNEL_BPF_HELPERS__
#define __CORE_PROBE_KERNEL_BPF_HELPERS__

#include <bpf/bpf_tracing.h>

#define MIN(a, b)	(((a) < (b)) ? (a) : (b))

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define BUILD_BUG_ON(cond)	_Static_assert(!(cond), "BUILD_BUG_ON failed " #cond)
#else
#define BUILD_BUG_ON(cond)
#endif

enum bpf_func_id___x { BPF_FUNC_get_func_ip___5_15_0 = 42 };

/* The following helpers validate skb offsets (mac, network & transport) as they
 * can be unset or invalid.
 *
 * The logic is the following:
 * - Most offsets can be invalidated using the special value ~0U.
 * - Some offsets can be initialized to 0, the value being invalid.
 * - All offsets can be reset using `skb->data - skb->head` (aka. headroom),
 *   which can be valid and a proper way to set the offset.
 *
 * `is_<offset>_valid` helpers check the offset value is valid but does not
 * check if the data pointed by that offset is. `is_<offset>_data_valid` do
 * check both.
 */

#define IS_UNSET(x)		((x) == (typeof(x))~0U)
#define IS_RESET(x, headroom)	((x) == (headroom))

static __always_inline bool is_mac_valid(u16 mac)
{
	/* Only check the mac offset was set, as it's the first of the offsets
	 * and could be equal to 0.
	 */
	return !IS_UNSET(mac);
}
static __always_inline bool is_network_valid(u16 network)
{
	return network && !IS_UNSET(network);
}
#define is_transport_valid is_network_valid

static __always_inline bool is_mac_data_valid(const struct sk_buff *skb)
{
	u16 mac, network;

	mac = BPF_CORE_READ(skb, mac_header);
	network = BPF_CORE_READ(skb, network_header);

	return is_mac_valid(mac) &&
	       !(is_network_valid(network) && network == mac &&
		 BPF_CORE_READ(skb, mac_len) == 0);
}

static __always_inline bool is_network_data_valid(const struct sk_buff *skb)
{
	u16 mac, network;

	mac = BPF_CORE_READ(skb, mac_header);
	network = BPF_CORE_READ(skb, network_header);

	return is_network_valid(network) &&
	       !(is_mac_valid(mac) && mac == network &&
		 BPF_CORE_READ(skb, mac_len) != 0);
}

static __always_inline bool is_transport_data_valid(struct sk_buff *skb)
{
	u16 network, transport;

	network = BPF_CORE_READ(skb, network_header);
	transport = BPF_CORE_READ(skb, transport_header);

	return is_transport_valid(transport) &&
	       !(is_network_valid(network) && network == transport);
}

#endif /* __CORE_PROBE_KERNEL_BPF_HELPERS__ */
