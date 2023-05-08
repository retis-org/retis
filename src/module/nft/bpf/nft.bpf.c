#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

#include <common.h>

#define NFT_NAME_SIZE 128

/* Please keep in sync with its Rust counterpart */
struct nft_event {
	char table_name[NFT_NAME_SIZE];
	char chain_name[NFT_NAME_SIZE];
	u32 verdict;
	char verdict_chain_name[NFT_NAME_SIZE];
	s64 t_handle;
	s64 c_handle;
	s64 r_handle;
} __attribute__((packed));

static __always_inline s64 nft_get_rule_handle(const struct nft_traceinfo *info,
					       const struct nft_verdict *verdict,
					       const struct nft_rule_dp *rule)
{
	if (!rule || !verdict || !info)
		return -1;

	if (BPF_CORE_READ_BITFIELD_PROBED(rule, is_last) ||
	    (BPF_CORE_READ_BITFIELD_PROBED(info, type) == NFT_TRACETYPE_RETURN) ||
	    (BPF_CORE_READ(verdict, code) == NFT_CONTINUE))
		return -1;

	return (u64)BPF_CORE_READ_BITFIELD_PROBED(rule, handle);
}

static __always_inline int nft_trace(struct nft_event *e,
				     const struct nft_traceinfo *info,
				     const struct nft_chain *chain,
				     const struct nft_verdict *verdict,
				     const struct nft_rule_dp *rule)
{
	char *name;

	/* Table info */
	name = BPF_CORE_READ(chain, table, name);
	bpf_probe_read_kernel_str(e->table_name, sizeof(e->table_name), name);

	/* Chain info */
	name = BPF_CORE_READ(chain, name);
	bpf_probe_read_kernel_str(e->chain_name, sizeof(e->chain_name), name);

	/* remaining info */
	e->verdict = (u32)BPF_CORE_READ(verdict, code);
	name = BPF_CORE_READ(verdict, chain, name);
	bpf_probe_read_kernel_str(e->verdict_chain_name,
				  sizeof(e->verdict_chain_name), name);
	e->t_handle = BPF_CORE_READ(chain, table, handle);
	e->c_handle = BPF_CORE_READ(chain, handle);
	e->r_handle = nft_get_rule_handle(info, verdict, rule);

	return 0;
}

struct nft_rule_dp_last___6_4_0 {
	const struct nft_chain *chain;	/* for nftables tracing */
} __attribute__((preserve_access_index));

static __always_inline
const struct nft_chain *nft_get_chain_from_rule(struct retis_context *ctx,
						struct nft_traceinfo *info,
						const struct nft_rule_dp *rule)
{
	const struct nft_rule_dp_last___6_4_0 *last;
	const struct nft_base_chain *base_chain;
	bool last_rule;
	u64 rule_dlen;
	int i;

	if (!rule) {
		base_chain = BPF_CORE_READ(info, basechain);
		if (!base_chain)
			return NULL;

		return (void *)base_chain +
			bpf_core_field_offset(base_chain->chain);
	}

	/* FIXME: This should ideally be bpf_core_type_exists(struct
	 * nft_rule_dp_last___6_4_0). For the time being this could not be
	 * done because of compilers and the way programs are built.
	 */
	if (!bpf_core_field_exists(info->rule)) {
		/* Make the loop bounded. 1024 has no specific
		 * meaning, just a reasonable value.
		 */
		for (i = 0; i < 1024; i++) {
			if (BPF_CORE_READ_BITFIELD_PROBED(rule, is_last)) {
				last = (void *)rule;
				break;
			}

			rule_dlen = BPF_CORE_READ_BITFIELD_PROBED(rule, dlen);
			rule = (void *)rule + sizeof(*rule) + rule_dlen;
		}

		return BPF_CORE_READ(last, chain);
	}

	return NULL;
}

/* Depending on the kernel:
 * - rule is under info, chain is a parameter
 * - rule is a parameter, chain is one of:
 *   - last_rule->chain
 *   - info->basechain->chain; if !rule
 *
 * The function deal with that and other than the rule, it also
 * retrieves the nft_chain pointer.
 */
static __always_inline
void nft_retrieve_rule(struct retis_context *ctx, struct nft_traceinfo *info,
		       const struct nft_rule_dp **rule, const struct nft_chain **chain)
{
	if (bpf_core_field_exists(info->rule)) {
		*chain = retis_get_nft_chain(ctx);
		*rule = BPF_CORE_READ(info, rule);
	}

	*rule = retis_get_nft_rule(ctx);
	*chain = nft_get_chain_from_rule(ctx, info, *rule);
}

static __always_inline
const struct nft_verdict *nft_get_verdict(struct retis_context *ctx,
					  struct nft_traceinfo *info)
{
	const struct nft_verdict *verdict;

	if (!bpf_core_field_exists(info->verdict))
		verdict = retis_get_nft_verdict(ctx);
	else
		verdict = BPF_CORE_READ(info, verdict);

	return verdict;
}


DEFINE_HOOK(F_AND, RETIS_F_PACKET_PASS,
	const struct nft_verdict *verdict;
	const struct nft_rule_dp *rule;
	const struct nft_chain *chain;
	struct nft_traceinfo *info;
	struct nft_event *e;

	/* nft_traceinfo pointer must be present. */
	info = retis_get_nft_traceinfo(ctx);
	if (!info)
		return 0;

	/* rule can be NULL. */
	nft_retrieve_rule(ctx, info, &rule, &chain);
	if (!chain)
		return 0;

	verdict = nft_get_verdict(ctx, info);

	e = get_event_zsection(event, COLLECTOR_NFT, 1, sizeof(*e));
	if (!e)
		return 0;

	return nft_trace(e, info, chain, verdict, rule);
)

char __license[] SEC("license") = "GPL";