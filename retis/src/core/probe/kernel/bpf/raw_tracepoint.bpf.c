#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include <common.h>

/* It is safe to have these values per-object as the loaded object won't be
 * shared between attached programs for raw tracepoints.
 */
const volatile u32 nargs = 0;

/* Only used in legacy mode where the raw tracepoint program can't be reused. */
const volatile u64 ksym = 0;

/* We unroll the loop bellow as the verifier disallow arithmetic operations on
 * context pointer. The loop unrolling pragma doesn't work here, do it manually,
 * keeping the "dynamic" fashion.
 */
static __always_inline void get_regs(struct retis_regs *regs,
				     struct bpf_raw_tracepoint_args *ctx)
{
#define arg_case(x)	\
	case x:		\
		regs->reg[x] = ctx->args[x];

	if (!nargs)
		return;

	switch (nargs - 1) {
	arg_case(11)
	arg_case(10)
	arg_case(9)
	arg_case(8)
	arg_case(7)
	arg_case(6)
	arg_case(5)
	arg_case(4)
	arg_case(3)
	arg_case(2)
	arg_case(1)
	arg_case(0)
	}

	regs->num = nargs;
}

SEC("raw_tracepoint/probe")
int probe_raw_tracepoint(struct bpf_raw_tracepoint_args *ctx)
{
	struct retis_context context = {};

	context.timestamp = bpf_ktime_get_ns();
	context.probe_type = KERNEL_PROBE_TRACEPOINT;
	context.orig_ctx = ctx;
	get_regs(&context.regs, ctx);

	/* Check if cookies can be set and retrieved from raw tracepoints,
	 * otherwise fallback to a per-program kernel symbol being provided.
	 */
	if (bpf_core_field_exists(((struct bpf_raw_tp_link *) 0)->cookie))
		context.ksym = bpf_get_attach_cookie(ctx);
	else
		context.ksym = ksym;

	return chain(&context);
}

char __license[] SEC("license") = "GPL";
