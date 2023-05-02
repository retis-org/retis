#ifndef __CORE_PROBE_KERNEL_BPF_CONTEXT__
#define __CORE_PROBE_KERNEL_BPF_CONTEXT__

#include <vmlinux.h>

enum kernel_probe_type {
	KERNEL_PROBE_KPROBE = 0,
	KERNEL_PROBE_KRETPROBE = 1,
	KERNEL_PROBE_TRACEPOINT = 2,
};

/* Per-probe parameter offsets; keep in sync with its Rust counterpart in
 * core::probe::kernel::config. A value of -1 means the argument isn't
 * available. Please try to reuse the targeted object names.
 */
struct retis_probe_offsets {
	s8 sk_buff;
	s8 skb_drop_reason;
	s8 net_device;
	s8 net;	 /* netns */
} __attribute__((packed));

/* Common representation of the register values provided to the probes, as this
 * is done in a per-probe type fashion.
 *
 * reg: registers values.
 * num: number of valid registers.
 */
struct retis_regs {
#define REG_MAX 12	/* Fexit max, let's use this */
	u64 reg[REG_MAX];
	u64 ret;
	u32 num;
};

/* Common context information consumed by all hooks. It serves as an abstraction
 * as different probe types have different specific contexts. This information
 * will be used to provide helpers for hooks as well, e.g. to safely retrieve a
 * function parameter.
 *
 * timestamp: Timestamp of when the probe wall called, should be filled as early
 *	    as possible in the probe specific part. Then it should be left
 *	    untouched.
 * ksym:      Symbol address of the where the probe was hooked. Should also be
 *	    filled in the probe specific part. It is quite handy as it is the
 *	    only common way of understanding where a probe/hook is running.
 * regs:      Common representation of the regs of the function being probed. It
 *	    can be used to retrieve parameters, and if the probe type allows,
 *	    the returned value. Should be accessed using the get_param()
 *	    helper.
 */
struct retis_context {
	enum kernel_probe_type probe_type;
	u64 timestamp;
	u64 ksym;
	struct retis_probe_offsets offsets;
	struct retis_regs regs;
	/* Pointer to the original ctx. Needed for helper calls. */
	void *orig_ctx;
	/* Contains the bits identifying what filters yield a hit outcome.
	 * A bit is set means that the filter matched the data based on its
	 * criteria .
	 */
	u32 filters_ret;
};

/* Helper to retrieve a function parameter argument using the common context */
#define retis_get_param(ctx, offset, type)	\
	(type)(((offset) >= 0 && (offset) < REG_MAX && (offset) < ctx->regs.num) ?	\
       ctx->regs.reg[offset] : 0)

/* Check if a given argument is valid */
#define retis_arg_valid(ctx, name)	\
	(ctx->offsets.name >= 0)

/* Argument specific helpers for use in generic hooks (and easier use in
 * targeted ones.
 */
#define RETIS_GET(ctx, name, type)		\
	(retis_arg_valid(ctx, name) ?		\
	 retis_get_param(ctx, ctx->offsets.name, type) : 0)

#define retis_get_sk_buff(ctx)		\
	RETIS_GET(ctx, sk_buff, struct sk_buff *)
#define retis_get_skb_drop_reason(ctx)	\
	RETIS_GET(ctx, skb_drop_reason, enum skb_drop_reason)
#define retis_get_net_device(ctx)	\
	RETIS_GET(ctx, net_device, struct net_device *)
#define retis_get_net(ctx)		\
	RETIS_GET(ctx, net, struct net *)

/* Keep in sync with its Rust counterpart in crate::core::probe::kernel */
#define PROBE_MAX	128

#endif /* __CORE_PROBE_KERNEL_BPF_CONTEXT__ */
