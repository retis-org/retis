#ifndef __CORE_PROBE_KERNEL_BPF_HELPERS__
#define __CORE_PROBE_KERNEL_BPF_HELPERS__

#include <bpf/bpf_tracing.h>

#define MIN(a, b)	(((a) < (b)) ? (a) : (b))

enum bpf_func_id___x { BPF_FUNC_get_func_ip___5_15_0 = 42 };

/* The following helper retrieves the function IP in kprobes.
 *
 * The proper way to get the function IP from a kprobe is by using
 * bpf_get_func_ip, which was introduced in Linux v5.15. If running on an older
 * kernel, we can get the current IP and compute the previous IP. But when
 * CONFIG_X86_KERNEL_IBT=y, indirect call landing sites and former ones will
 * have an extra endbr or nop4 instruction making the function IP +4 further up;
 * in such cases the only way to retrieve the function IP is also by using
 * bpf_get_func_ip.
 *
 * However, support for bpf_get_func_ip, CONFIG_X86_KERNEL_IBT option and its
 * handling in bpf_get_func_ip were done in different commits, merged into
 * different kernel versions, with no Fixes: tag. So we might end up in a
 * situation where CONFIG_X86_KERNEL_IBT=y and bpf_get_func_ip does not support
 * it. Our strategy is to always use bpf_get_func_ip if available and still use
 * the manual computation otherwise to allow some stable/downstream kernels to
 * work. We can't do much more and it might happen that some kernels with
 * CONFIG_X86_KERNEL_IBT=y and bpf_get_func_ip won't work. Hopefully that should
 * be rare, and even less common over time.
 */
static __always_inline u64 kprobe_get_func_ip(struct pt_regs *ctx) {
	if (bpf_core_enum_value_exists(enum bpf_func_id___x, BPF_FUNC_get_func_ip___5_15_0))
		return bpf_get_func_ip(ctx);
	else
		return PT_REGS_IP(ctx) - 1;
}

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

static __always_inline bool is_mac_data_valid(struct sk_buff *skb)
{
	u16 mac, network;

	mac = BPF_CORE_READ(skb, mac_header);
	network = BPF_CORE_READ(skb, network_header);

	return is_mac_valid(mac) &&
	       !(is_network_valid(network) && network == mac &&
		 BPF_CORE_READ(skb, mac_len) == 0);
}

static __always_inline bool is_network_data_valid(struct sk_buff *skb)
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
