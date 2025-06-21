#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>
#include <dev_common.h>

/* Attach to netdev_core_stats_inc(struct net_device *dev, u32 offset) */
DEFINE_HOOK_RAW(
	struct dev_core_stat_event *e;

	e = get_event_section(event, COLLECTOR_DEV, SECTION_CORE_STAT,
			      sizeof(*e));
	if (!e)
		return 0;

	e->offset = (u32)ctx->regs.reg[1];

	return 0;
)

char __license[] SEC("license") = "GPL";
