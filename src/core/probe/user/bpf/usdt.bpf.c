#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

#include <user_common.h>

/* Hook placeholder */
__attribute__ ((noinline))
int hook0(struct user_ctx *ctx, struct retis_raw_event *event) {
	volatile int ret = 0;
	if (!ctx || !event)
		return 0;
	return ret;
}

static __always_inline int get_args(struct user_ctx *uctx,
				     struct pt_regs *ctx)
{
	int cnt = bpf_usdt_arg_cnt(ctx);
	long tmp = 0;

#define arg_case(x)								\
	case x:									\
		if (bpf_usdt_arg(ctx, x, &tmp))					\
			return -1;						\
		uctx->args[x] = tmp;						\

	if (!cnt)
		return 0;

	switch (cnt - 1) {
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
	uctx->num = cnt;

	return 0;
}

SEC("usdt")
int probe_usdt(struct pt_regs *ctx)
{
	struct pt_regs ctx_fp = *ctx;
	volatile u16 pass_threshold;
	struct common_event *e;
	struct retis_raw_event *event;
	struct user_event *u;
	struct user_ctx uctx = {};

	if (get_args(&uctx, ctx) != 0)
		return -1;

	event = get_event();
	if (!event)
		return 0;

	e = get_event_section(event, COMMON, 1, sizeof(*e));
	if (!e) {
		discard_event(event);
		return 0;
	}

	uctx.timestamp = bpf_ktime_get_ns();
	e->timestamp = uctx.timestamp;

	u = get_event_section(event, USERSPACE, 1, sizeof(*u));
	if (!u) {
		discard_event(event);
		return 0;
	}
	u->symbol = PT_REGS_IP(ctx);
	u->pid = bpf_get_current_pid_tgid();
	u->event_type = USDT;

	pass_threshold = get_event_size(event);

	/* UST only supports a single hook. */
	hook0(&uctx, event);

	if (get_event_size(event) <= pass_threshold)
		discard_event(event);
	else
		send_event(event);

	return 0;
}

char __license[] SEC("license") = "GPL";
