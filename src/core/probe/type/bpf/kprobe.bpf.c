#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <common.h>

static __always_inline void get_regs(struct pt_regs *ctx, struct regs *regs)
{
	regs->param[0] = PT_REGS_PARM1(ctx);
	regs->param[1] = PT_REGS_PARM2(ctx);
	regs->param[2] = PT_REGS_PARM3(ctx);
	regs->param[3] = PT_REGS_PARM4(ctx);
	regs->param[4] = PT_REGS_PARM5(ctx);
	regs->num = 5;
}

SEC("kprobe/probe")
int probe_kprobe(struct pt_regs *ctx)
{
	struct trace_context context = {};

	context.timestamp = bpf_ktime_get_ns();
	context.ksym = PT_REGS_IP(ctx) - 1;
	get_regs(ctx, &context.regs);

	return chain(&context);
}

char __license[] SEC("license") = "GPL";
