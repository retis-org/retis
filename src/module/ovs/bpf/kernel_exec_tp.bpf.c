#include <openvswitch.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include "ovs_common.h"
#include "netlink.h"

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct exec_event {
	u8 action;
	u32 recirc_id;
} __attribute__((packed));

/* Hook for ovs_do_execute_action tracepoint. */
DEFINE_HOOK(
	struct nlattr *attr;
	struct sw_flow_key *key;
	struct exec_event *exec;

	key = (struct sw_flow_key *) ctx->regs.reg[2];
	if (!key)
		return 0;

	attr = (struct nlattr *) ctx->regs.reg[3];
	if (!attr)
		return 0;

	exec = get_event_section(event, COLLECTOR_OVS, OVS_DP_EXEC,
				 sizeof(*exec));
	if (!exec)
		return 0;

	exec->action = nla_type(attr);
	exec->recirc_id = BPF_CORE_READ(key, recirc_id);

	return 0;
)

char __license[] SEC("license") = "GPL";
