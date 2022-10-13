#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <common.h>

const volatile u32 ksym = 0;
const volatile u32 last_arg = 0;

static __always_inline void get_regs(struct bpf_raw_tracepoint_args *ctx,
				     struct regs *regs)
{
	int i;

	for (i = 0; i <= last_arg; i++)
		regs->param[i] = ctx->args[i];
	regs->num = i;
}

SEC("raw_tracepoint/probe")
int probe_raw_tracepoint(struct bpf_raw_tracepoint_args *ctx)
{
	struct trace_context context = {0};

	context.timestamp = bpf_ktime_get_ns();
	context.ksym = ksym;
	get_regs(ctx, &context.regs);

	return chain(&context);
}

char __license[] SEC("license") = "GPL";
