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
	u64 pid = bpf_get_current_pid_tgid();
	u64 sym_addr = PT_REGS_IP(ctx);
	struct retis_raw_event *event;
	struct common_task_event *ti;
	static bool enabled = false;
	volatile u16 pass_threshold;
	struct user_ctx uctx = {};
	struct common_event *e;
	struct user_event *u;

	/* Check if the collection is enabled, otherwise bail out. Once we have
	 * a positive result, cache it.
	 */
	if (unlikely(!enabled)) {
		enabled = collection_enabled();
		if (!enabled)
			return 0;
	}

	if (get_args(&uctx, ctx) != 0)
		return -1;

	event = get_event();
	if (!event) {
		err_report(sym_addr, pid >> 32);
		return 0;
	}

	e = get_event_section(event, COMMON, COMMON_SECTION_CORE, sizeof(*e));
	if (!e)
		goto discard_event;

	uctx.timestamp = bpf_ktime_get_ns();
	e->timestamp = uctx.timestamp;
	e->smp_id = bpf_get_smp_processor_id();

	ti = get_event_zsection(event, COMMON, COMMON_SECTION_TASK, sizeof(*ti));
	if (!ti)
		goto discard_event;

	ti->pid = pid;
	bpf_get_current_comm(ti->comm, sizeof(ti->comm));

	u = get_event_section(event, USERSPACE, 1, sizeof(*u));
	if (!u)
		goto discard_event;

	u->symbol = sym_addr;
	u->pid = pid;
	u->event_type = USDT;

	pass_threshold = get_event_size(event);
	barrier_var(pass_threshold);

	/* UST only supports a single hook. */
	hook0(&uctx, event);

	if (get_event_size(event) > pass_threshold) {
		send_event(event);
		return 0;
	}

discard_event:
	discard_event(event);

	return 0;
}

char __license[] SEC("license") = "GPL";
