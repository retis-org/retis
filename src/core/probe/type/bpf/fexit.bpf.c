#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <common.h>

const volatile u32 ksym = 0;
const volatile u32 ret_off = 0;

static __always_inline void get_regs(unsigned long long *ctx, struct regs *regs)
{
#define arg_case(n)     \
	case n:         \
		regs->param[n] = ctx[n];
	switch (ret_off) {
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

	regs->num = ret_off;
}

SEC("fexit/probe")
int probe_fexit(unsigned long long *ctx)
{
	struct trace_context context = {};

	context.timestamp = bpf_ktime_get_ns();
	context.ksym = ksym;
	get_regs(ctx, &context.regs);

	return chain(&context);
}

char __license[] SEC("license") = "GPL";
