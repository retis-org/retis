#ifndef __CORE_PROBE_USER_BPF_COMMON__
#define __CORE_PROBE_USER_BPF_COMMON__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

#include <events.h>
#include <common_defs.h>

enum userspace_event_type {
	USDT = 1,
};

/* Userspace section of the event data. */
struct user_event {
	u64 symbol;
	u64 pid;
	u8  event_type;
} __attribute__((packed));

/* Userspace context */
struct user_ctx {
	long args[BPF_USDT_MAX_ARG_CNT];
	u32 num;
	u64 timestamp;
};

/* Helper to define a USDT hook (mostly in collectors) while not having to
 * duplicate the common part everywhere.
 * This also ensure hooks are doing the right thing and should help with
 * maintenance.
 *
 * To define a USDT hook in a collector hook, say hook.bpf.c,
 * ```
 * #include <user_common.h>
 *
 * DEFINE_USDT_HOOK(
 *	long myarg = ctx->args[0];
 *	do_something(myarg, event);
 *	return 0;
 * )
 *
 * char __license[] SEC("license") = "GPL";
 * ```
 *
 * Do not forget to add the hook to build.rs
 */
#define DEFINE_USDT_HOOK(inst)							\
	SEC("ext/hook")								\
	int hook(struct user_ctx *ctx, struct retis_raw_event *event)		\
	{									\
		/* Let the verifier be happy */					\
		if (!ctx || !event)						\
			return 0;						\
		inst								\
	}

#endif // __CORE_PROBE_USER_BPF_COMMON__
