#ifndef __CORE_PROBE_KERNEL_BPF_COMPAT__
#define __CORE_PROBE_KERNEL_BPF_COMPAT__

struct nft_rule___3_13_0 {
	u64 handle:42;
} __attribute__((preserve_access_index));

struct nft_rule_dp___5_17_0 {
	u64 is_last:1,
	    handle:42;
} __attribute__((preserve_access_index));

struct nft_traceinfo___6_3_0 {
	const struct nft_pktinfo *pkt;
	const struct nft_rule_dp *rule;
	const struct nft_verdict *verdict;
} __attribute__((preserve_access_index));

struct nft_rule_dp_last___6_4_0 {
	const struct nft_chain *chain;
} __attribute__((preserve_access_index));

struct sk_buff___6_1_0 {
       u8 vlan_present:1;
} __attribute__((preserve_access_index));

#endif /* __CORE_PROBE_KERNEL_BPF_COMPAT__ */
