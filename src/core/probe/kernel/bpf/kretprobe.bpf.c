#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <common.h>

#define MAX_INFLIGHT_PROBES 20
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_INFLIGHT_PROBES);
	__type(key, u64);
	__type(value, struct retis_context);
} kretprobe_context SEC(".maps");

/* Merge the registers with the ones coming from the matching kprobe */
static __always_inline void kretprobe_get_regs(struct retis_regs *regs,
					       struct retis_regs *kprobe_regs,
					       struct pt_regs *ctx)
{
	regs->reg[0] = kprobe_regs->reg[0];
	regs->reg[1] = kprobe_regs->reg[1];
	regs->reg[2] = kprobe_regs->reg[2];
	regs->reg[3] = kprobe_regs->reg[3];
	regs->reg[4] = kprobe_regs->reg[4];
	regs->num = kprobe_regs->num;

	regs->ret = PT_REGS_RC(ctx);
}

static __always_inline void kprobe_get_regs(struct retis_regs *regs,
					    struct pt_regs *ctx)
{
	regs->reg[0] = PT_REGS_PARM1(ctx);
	regs->reg[1] = PT_REGS_PARM2(ctx);
	regs->reg[2] = PT_REGS_PARM3(ctx);
	regs->reg[3] = PT_REGS_PARM4(ctx);
	regs->reg[4] = PT_REGS_PARM5(ctx);
	regs->num = 5;
}

SEC("kretprobe/probe")
int probe_kretprobe(struct pt_regs *ctx)
{
	struct retis_context context = {};
	struct retis_context *kprobe_ctx;
	u64 tid = bpf_get_current_pid_tgid();

	/* Look if the matching kprobe has left a context for us to pick up. */
	kprobe_ctx = bpf_map_lookup_elem(&kretprobe_context, &tid);
	if (!kprobe_ctx) {
		return 0;
	}
	bpf_map_delete_elem(&kretprobe_context, &tid);

	context.timestamp = bpf_ktime_get_ns();
	context.ksym = kprobe_ctx->ksym;
	context.probe_type = KERNEL_PROBE_KRETPROBE;
	context.orig_ctx = ctx;

	kretprobe_get_regs(&context.regs, &kprobe_ctx->regs, ctx);

	return chain(&context);
}

SEC("kprobe/probe")
int probe_kprobe(struct pt_regs *ctx)
{
	struct retis_context context = {};
	u64 tid = bpf_get_current_pid_tgid();

	context.timestamp = bpf_ktime_get_ns();
	context.ksym = kprobe_get_func_ip(ctx);
	kprobe_get_regs(&context.regs, ctx);

	/* Store the current context and let the kretprobe run the hooks. */
	if (!bpf_map_update_elem(&kretprobe_context, &tid, &context, BPF_NOEXIST)) {
		return -1;
	}
	return 0;
}

char __license[] SEC("license") = "GPL";
