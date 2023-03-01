#include <openvswitch.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include "ovs_common.h"
#include "netlink.h"

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct exec_event {
	u8 action;
	u32 recirc_id;
	u32 queue_id;
} __attribute__((packed));

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct exec_output {
	u32 port;
} __attribute__((packed));


static __always_inline u32 queue_id_gen(struct retis_context *ctx)
{
	struct sk_buff *skb;
	int zero = 0;
	u64 tid = bpf_get_current_pid_tgid();
	if (!bpf_map_lookup_elem(&inflight_exec_cmd, &tid)) {
		/* This call to ovs_do_execute_action does not come from a
		* userspace command. */
		return 0;
	}

	skb = (struct sk_buff *) ctx->regs.reg[1];
	if (!skb)
		return 0;

	struct packet_buffer *buff = bpf_map_lookup_elem(&packet_buffers,
							 &zero);
    if (!buff)
        return 0;

	return hash_skb(buff, skb, 0);
}

/* Hook for ovs_do_execute_action tracepoint. */
DEFINE_HOOK(
	struct nlattr *attr;
	struct sw_flow_key *key;
	struct exec_event *exec;

	key= (struct sw_flow_key *) ctx->regs.reg[2];
	if (!key)
		return 0;

	attr = (struct nlattr *) ctx->regs.reg[3];
	if (!attr)
		return 0;

	exec = get_event_section(event, COLLECTOR_OVS, OVS_DP_ACTION,
				 sizeof(*exec));
	if (!exec)
		return 0;

	exec->action = nla_type(attr);
	exec->recirc_id = BPF_CORE_READ(key, recirc_id);
	exec->queue_id = queue_id_gen(ctx);

	// Add action-specific data for some actions.
	switch (exec->action) {
	case OVS_ACTION_ATTR_OUTPUT:
		{
		struct exec_output *output =
			get_event_section(event, COLLECTOR_OVS,
					  OVS_DP_ACTION_OUTPUT,
					  sizeof(*output));
		if (!output)
			return 0;

		bpf_probe_read_kernel(&output->port, sizeof(output->port),
				      nla_data(attr));
		break;
		}
	}

	return 0;
)

char __license[] SEC("license") = "GPL";