#ifndef __CORE_PROBE_KERNEL_BPF_COMMON__
#define __CORE_PROBE_KERNEL_BPF_COMMON__

#include <vmlinux.h>

/* Common representation of the register values provided to the probes, as this
 * is done in a per-probe type fashion.
 *
 * reg: registers values.
 * num: number of valid registers.
 */
struct trace_regs {
#define REG_MAX 12	/* Fexit max, let's use this */
	u64 reg[REG_MAX];
	u32 num;
};

/* Common context information consumed by all hooks. It serves as an abstraction
 * as different probe types have different specific contexts. This information
 * will be used to provide helpers for hooks as well, e.g. to safely retrieve a
 * function parameter.
 *
 * timestamp: Timestamp of when the probe wall called, should be filled as early
 *            as possible in the probe specific part. Then it should be left
 *            untouched.
 * ksym:      Symbol address of the where the probe was hooked. Should also be
 *            filled in the probe specific part. It is quite handy as it is the
 *            only common way of understanding where a probe/hook is running.
 * regs:      Common representation of the regs of the function being probed. It
 *            can be used to retrieve parameters, and if the probe type allows,
 *            the returned value. Should be accessed using the get_param()
 *            helper.
 */
struct trace_context {
	u64 timestamp;
	u64 ksym;
	struct trace_regs regs;
};

/* Helper to retrieve a function parameter argument using the common context */
#define trace_get_param(ctx, offset, type)	\
	(type)(((offset) >= 0 && (offset) < REG_MAX && (offset) < ctx->regs.num) ?	\
       ctx->regs.reg[offset] : 0)

#endif /* __CORE_PROBE_KERNEL_BPF_COMMON__ */
