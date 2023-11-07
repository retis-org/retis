#ifndef __CORE_FILTERS_META_FILTER__
#define __CORE_FILTERS_META_FILTER__

/* Please keep in sync with its Rust counterpart. */
#define META_OPS_MAX	32
#define META_TARGET_MAX	32

enum retis_meta_cmp {
	RETIS_EQ = 0,
	RETIS_GT = 1,
	RETIS_LT = 2,
	RETIS_GE = 3,
	RETIS_LE = 4,
	RETIS_NE = 5,
};

enum retis_meta_type {
	RETIS_CHAR = 1,
	RETIS_SHORT,
	RETIS_INT,
	RETIS_LONG,
};

union retis_meta_op {
	struct {
		u8 type;
		u8 nmemb;
		u16 offt;
	} l;
	struct {
		union {
			u8 bin[META_TARGET_MAX];
			u64 num;
		} u;
		u8 sz;
		u8 cmp;
	} t;
};

/* Probe configuration; the key is the target symbol address */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, META_OPS_MAX);
	__type(key, u32);
	__type(value, union retis_meta_op);
} filter_meta_map SEC(".maps");

struct retis_meta_ctx {
	/* base address to read from. */
	void *base;
	/* relative to base. */
	u16 offset;
	/* type of leaf value. */
	u8 type;
	/* optional */
	u8 nmemb;
	/* Target Info */
	/* actual data. */
	void *data;
	/* size of data (optional). */
	u8 sz;
	/* operation. */
	u8 cmp;
};

#define PTR_BIT 1 << 6
#define SIGN_BIT 1 << 7

/* Global ro variable that identifies the number of elements in
 * filter_meta_map. Zero mean, no filter.
 */
const volatile u32 nmeta = 0;

static __always_inline long meta_process_ops(struct retis_meta_ctx *ctx)
{
	union retis_meta_op *val;
	u32 k = 0;
	u64 ptr;
	u32 i;

	val = bpf_map_lookup_elem(&filter_meta_map, &k);
	if (!val)
		return -1;

	/* process target */
	ctx->data = &val->t.u;
	ctx->cmp = val->t.cmp;
	ctx->sz = val->t.sz;

	for (i = 1, k = 1; i < nmeta; k++, i++) {
		val = bpf_map_lookup_elem(&filter_meta_map, &k);
		if (!val)
			return -1;

		/* Load Pointer */
		if (val->l.type == PTR_BIT) {
			if (bpf_probe_read_kernel(&ptr, sizeof(void *),
						  (char *)ctx->base + (val->l.offt)))
				return -1;

			ctx->base = (void *)ptr;
			continue;
		}

		/* Non intermediate */
		ctx->offset = val->l.offt;
		ctx->type = val->l.type;
		ctx->nmemb = val->l.nmemb;
	}

	return 0;
}

static __always_inline
bool cmp_num(u64 operand1, u64 operand2, bool sign_bit, u8 cmp_type)
{
	switch (cmp_type) {
	case RETIS_EQ:
		return (operand1 == operand2);
	case RETIS_NE:
		return (operand1 != operand2);
	case RETIS_GT:
		return sign_bit ? ((s64)operand1 > (s64)operand2) : ((u64)operand1 > (u64)operand2);
	case RETIS_LT:
		return sign_bit ? ((s64)operand1 < (s64)operand2) : ((u64)operand1 < (u64)operand2);
	case RETIS_GE:
		return sign_bit ? ((s64)operand1 >= (s64)operand2) : ((u64)operand1 >= (u64)operand2);
	case RETIS_LE:
		return sign_bit ? ((s64)operand1 <= (s64)operand2) : ((u64)operand1 <= (u64)operand2);
	default:
		/* FIXME: report error. */
		break;
	}

	return false;
}

static __always_inline
bool filter_bytes(struct retis_meta_ctx *ctx)
{
	char val[META_TARGET_MAX];
	u32 sz;

	/* if it is an array of chars use its size. Alternatively, use
	 * the target size (probe read could fail in this case).
	 * Note: for some reason the one-liner version of this fails to
	 * generate code accepted by the verifier. Broken in two lines
	 * to workaround that issue.
	 */
	sz = ctx->nmemb ? : ctx->sz;
	sz = MIN(sz, sizeof(val));

	if (bpf_probe_read_kernel_str(val, sz, (char *)ctx->base + ctx->offset) < 0)
		return 0;

	if (!sz)
		return false;

	const char *sp1 = ctx->data, *sp2 = val;
	/* A redundant bound check (sz < META_OPS_MAX) here is
	 * needed to pass the verification stage
	 */
	while (sz-- > 0 && sz < META_OPS_MAX &&
	       *sp1 && *sp2 && !(*sp1 - *sp2))
		sp1++, sp2++;

	return !(*sp1 - *sp2);
}

static __always_inline u64 fixup_signed(u64 val, u32 sz)
{
	u64 ret;

	switch (sz) {
	case 4:
		ret = (u64)(s32)val;
		break;
	case 2:
		ret = (u64)(s16)val;
		break;
	case 1:
		ret = (u64)(s8)val;
		break;
	default:
		ret = val;
		break;
	}

	return ret;
}

static __always_inline
unsigned int filter_num(struct retis_meta_ctx *ctx)
{
	bool sign_bit = ctx->type & SIGN_BIT;
	u64 tval, mval = 0;
	u32 sz;

	sz = MIN(ctx->sz, sizeof(mval));

	if (bpf_probe_read_kernel(&mval, sz, (char *)ctx->base + ctx->offset))
		return 0;

	tval = *((u64 *)ctx->data);

	if (sign_bit)
		mval = fixup_signed(mval, sz);

	return cmp_num(mval, tval, sign_bit, ctx->cmp);
}

static __always_inline
unsigned int meta_filter(struct sk_buff *skb)
{
	struct retis_meta_ctx ctx = {};
	u8 __nmemb, __type;

	/* reduce actions to load/cmp info. If no entries, return
	 * match.
	 */
	if (!nmeta || nmeta > META_OPS_MAX)
		return 1;

	ctx.base = skb;

	if (meta_process_ops(&ctx) < 0 || !ctx.data)
		return 0;

	if (ctx.type & PTR_BIT || ctx.nmemb > 0)
		return filter_bytes(&ctx);

	return filter_num(&ctx);
}

#endif
