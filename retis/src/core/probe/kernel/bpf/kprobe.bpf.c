#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <common.h>

static __always_inline void get_regs(struct retis_regs *regs, struct pt_regs *ctx)
{
	regs->reg[0] = PT_REGS_PARM1(ctx);
	regs->reg[1] = PT_REGS_PARM2(ctx);
	regs->reg[2] = PT_REGS_PARM3(ctx);
	regs->reg[3] = PT_REGS_PARM4(ctx);
	regs->reg[4] = PT_REGS_PARM5(ctx);
	regs->num = 5;
}

SEC("kprobe/probe")
int probe_kprobe(struct pt_regs *ctx)
{
	struct retis_context context = {};

	context.timestamp = bpf_ktime_get_ns();
	context.ksym = kprobe_get_func_ip(ctx);
	context.probe_type = KERNEL_PROBE_KPROBE;
	context.orig_ctx = ctx;
	get_regs(&context.regs, ctx);

	return chain(&context);
}

char __license[] SEC("license") = "GPL";
