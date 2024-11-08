#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include <compat.h>

#define VERD_SCALE (NFT_RETURN * -1)
#define ALLOWED_VERDICTS(verd, mask) (1 << (verd + VERD_SCALE) & mask)
#define NFT_NAME_SIZE 128

#define retis_get_nft_chain(ctx, cfg)		\
	RETIS_HOOK_GET(ctx, cfg->offsets, nft_chain, struct nft_chain *)
#define retis_get_nft_rule(ctx, cfg)		\
	RETIS_HOOK_GET(ctx, cfg->offsets, nft_rule, struct nft_rule_dp *)
#define retis_get_nft_verdict(ctx, cfg)		\
	RETIS_HOOK_GET(ctx, cfg->offsets, nft_verdict, struct nft_verdict *)
#define retis_get_nft_type(ctx, cfg)		\
	RETIS_HOOK_GET(ctx, cfg->offsets, nft_type, enum nft_trace_types)

/**
 * Nft hook configuration.
 *
 * Skip Default trait implementation:
 *
 * <div rustbindgen nodefault></div>
 */
struct nft_offsets {
	s8 nft_chain;
	s8 nft_rule;
	s8 nft_verdict;
	s8 nft_type;
};
struct nft_config {
	u64 verdicts;
	struct nft_offsets offsets;
} __binding;
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct nft_config);
} nft_config_map SEC(".maps");

struct nft_event {
	char table_name[NFT_NAME_SIZE];
	char chain_name[NFT_NAME_SIZE];
	u32 verdict;
	char verdict_chain_name[NFT_NAME_SIZE];
	s64 t_handle;
	s64 c_handle;
	s64 r_handle;
	u8 policy;
} __binding;

/* Specialized macro. Deals with different types with similar layout. */
#define __nft_get_rule_handle(__info, __verdict, __rule) ({	\
	if (BPF_CORE_READ_BITFIELD_PROBED(info, type) == NFT_TRACETYPE_RETURN && \
	    BPF_CORE_READ(verdict, code) == NFT_CONTINUE)	\
		return -1;					\
	(u64)BPF_CORE_READ_BITFIELD_PROBED(__rule, handle); })

/* Handles both legacy and current upstream types. is_last for
 * nft_rule_dp acts as a flag to identify a trailing rule and acts
 * as a NULL rule marker.
 */
static __always_inline s64 nft_get_rule_handle(const struct nft_traceinfo *info,
					       const struct nft_verdict *verdict,
					       const void *rule)
{
	if (!rule || !verdict || !info)
		return -1;

	if (bpf_core_type_exists(struct nft_rule_dp___5_17_0)) {
		const struct nft_rule_dp___5_17_0 *r = rule;
		if (BPF_CORE_READ_BITFIELD_PROBED(r, is_last))
			return -1;

		return __nft_get_rule_handle(info, verdict, r);
	} else if (bpf_core_type_exists(struct nft_rule___3_13_0)){
		const struct nft_rule___3_13_0 *r = rule;
		return __nft_get_rule_handle(info, verdict, r);
	} else {
		/* This should emit a warning that must be returned by
		 * userspace.
		 */
		return -1;
	}
}

static __always_inline int nft_trace(struct nft_config *cfg,
				     struct retis_raw_event *event,
				     const struct nft_traceinfo *info,
				     const struct nft_chain *chain,
				     const struct nft_verdict *verdict,
				     const void *rule,
				     enum nft_trace_types type)
{
	struct nft_event *e;
	char *name;
	u8 policy;
	u32 code;

	policy = (type == NFT_TRACETYPE_POLICY);
	code = policy ? (u32)BPF_CORE_READ(info, basechain, policy) :
		(u32)BPF_CORE_READ(verdict, code);
	if (!ALLOWED_VERDICTS(code, cfg->verdicts))
		return -ENOMSG;

	e = get_event_zsection(event, COLLECTOR_NFT, 1, sizeof(*e));
	if (!e)
		return 0;

	e->policy = policy;
	e->verdict = code;
	/* Table info */
	name = BPF_CORE_READ(chain, table, name);
	bpf_probe_read_kernel_str(e->table_name, sizeof(e->table_name), name);

	/* Chain info */
	name = BPF_CORE_READ(chain, name);
	bpf_probe_read_kernel_str(e->chain_name, sizeof(e->chain_name), name);

	name = BPF_CORE_READ(verdict, chain, name);
	bpf_probe_read_kernel_str(e->verdict_chain_name,
				  sizeof(e->verdict_chain_name), name);
	e->t_handle = BPF_CORE_READ(chain, table, handle);
	e->c_handle = BPF_CORE_READ(chain, handle);
	e->r_handle = nft_get_rule_handle(info, verdict, rule);

	return 0;
}

static __always_inline
const struct nft_chain *nft_get_chain_from_rule(struct retis_context *ctx,
						struct nft_traceinfo *info,
						const struct nft_rule_dp *rule)
{
	const struct nft_rule_dp_last___6_4_0 *last = NULL;
	const struct nft_base_chain *base_chain;
	struct nft_traceinfo___6_3_0 *info_63;
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
	info_63 = (struct nft_traceinfo___6_3_0 *)info;
	if (!bpf_core_field_exists(info_63->rule)) {
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
 *   - rule type is nft_rule
 *   - rule type is nft_rule_dp
 * - rule is a parameter, chain is one of:
 *   - last->chain; if rule->is_last
 *   - info->basechain->chain; if !rule
 *
 * The function deal with that and other than the rule, it also
 * retrieves the nft_chain pointer.
 */
static __always_inline
void nft_retrieve_rule(struct retis_context *ctx, struct nft_config *cfg,
		       struct nft_traceinfo *info,
		       const void **rule,
		       const struct nft_chain **chain)
{
	struct nft_traceinfo___6_3_0 *info_63;

	info_63 = (struct nft_traceinfo___6_3_0 *)info;
	if (bpf_core_field_exists(info_63->rule)) {
		*chain = retis_get_nft_chain(ctx, cfg);
		*rule = BPF_CORE_READ(info_63, rule);
		return;
	}

	*rule = retis_get_nft_rule(ctx, cfg);
	*chain = nft_get_chain_from_rule(ctx, info, *rule);
}

static __always_inline
const struct nft_verdict *nft_get_verdict(struct retis_context *ctx,
					  struct nft_config *cfg,
					  struct nft_traceinfo *info)
{
	struct nft_traceinfo___6_3_0 *info_63;
	const struct nft_verdict *verdict;

	info_63 = (struct nft_traceinfo___6_3_0 *)info;
	if (!bpf_core_field_exists(info_63->verdict))
		verdict = retis_get_nft_verdict(ctx, cfg);
	else
		verdict = BPF_CORE_READ(info_63, verdict);

	return verdict;
}


DEFINE_HOOK(F_AND, RETIS_ALL_FILTERS,
	const struct nft_verdict *verdict;
	const struct nft_chain *chain;
	struct nft_traceinfo *info;
	struct nft_config *cfg;
	const void *rule;
	u32 zero = 0;

	cfg = bpf_map_lookup_elem(&nft_config_map, &zero);
	if (!cfg)
		return 0;

	/* nft_traceinfo pointer must be present. */
	info = retis_get_nft_traceinfo(ctx);
	if (!info)
		return 0;

	/* rule can be NULL. */
	nft_retrieve_rule(ctx, cfg, info, &rule, &chain);
	if (!chain)
		return 0;

	verdict = nft_get_verdict(ctx, cfg, info);

	return nft_trace(cfg, event, info, chain, verdict, rule,
			 retis_get_nft_type(ctx, cfg));
)

char __license[] SEC("license") = "GPL";
