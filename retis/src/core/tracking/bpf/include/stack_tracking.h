#ifndef __CORE_STACK_TRACKING__
#define __CORE_STACK_TRACKING__

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <events.h>
#include <common_defs.h>
#include <helpers.h>
#include <retis_context.h>

const volatile unsigned int THREAD_SIZE;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, u64);
} stack_tracking_map SEC(".maps");

/* we have to pass around `u64 *` otherwise
 * this will fail for the non-kprobe case (&ctx)
 */
__noinline u64 get_base_addr(u64 *saddr)
{
	if (!saddr)
		return 0;

	return *saddr & ~(THREAD_SIZE - 1UL);
}

static __always_inline u64 get_stack_addr(void *ctx, enum kernel_probe_type type)
{
	u64 addr;

	switch (type) {
	case KERNEL_PROBE_KRETPROBE:
		fallthrough;
	case KERNEL_PROBE_KPROBE:
		if (!kprobe_multi_has_cookies()) {
			addr = PT_REGS_SP((struct pt_regs *)ctx);
			break;
		}

		fallthrough;
	default:
		addr = (u64)ctx;
		break;
	}

	/* Sanity check mostly against pt_regs. */
	if (!addr)
		log_error("Unexpected kernel stack base address (0).");

	return addr;
}

static __always_inline u64 get_stack_base(void *ctx, enum kernel_probe_type type)
{
	u64 stack_addr = get_stack_addr(ctx, type);

	return get_base_addr(&stack_addr);
}

static __always_inline u64 track_stack_update(u64 key, u64 value)
{
	u64 addr = value;

	if (!bpf_map_update_elem(&stack_tracking_map, &key,
				 &addr, BPF_ANY))
		return addr;

	return 0;
}

static __always_inline long track_stack_end(u64 stack_base)
{
	return bpf_map_delete_elem(&stack_tracking_map, &stack_base);
}

static __always_inline u64 stack_get_skb_ref(u64 stack_base)
{
	u64 *val;

	val = bpf_map_lookup_elem(&stack_tracking_map, &stack_base);
	if (!val)
		return 0;

	return *val;
}

static __always_inline bool stack_is_tracked(u64 stack_base)
{
	return stack_get_skb_ref(stack_base);
}

#endif /* __CORE_STACK_TRACKING__ */
