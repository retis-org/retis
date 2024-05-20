#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

#include <common.h>
#include <ovs_common.h>
#include <ovs_uapi.h>
#include <netlink.h>

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct exec_event {
	u8 action;
	u32 recirc_id;
};

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct exec_track_event {
	u32 queue_id;
};

/* Please keep in sync with its Rust counterpart in retis-events::ovs. */
struct exec_output {
	u32 port;
};

/* Please keep in sync with its Rust counterpart in retis-events::ovs. */
struct exec_recirc {
	u32 id;
};

/* Please keep in sync with its Rust counterpart in retis-events::ovs. */
#define R_OVS_CT_COMMIT				(1 << 0)
#define R_OVS_CT_FORCE				(1 << 1)
#define R_OVS_CT_IP4				(1 << 2)
#define R_OVS_CT_IP6				(1 << 3)
#define R_OVS_CT_NAT				(1 << 4)
#define R_OVS_CT_NAT_SRC			(1 << 5)
#define R_OVS_CT_NAT_DST			(1 << 6)
#define R_OVS_CT_NAT_RANGE_MAP_IPS		(1 << 7)
#define R_OVS_CT_NAT_RANGE_PROTO_SPECIFIED	(1 << 8)
#define R_OVS_CT_NAT_RANGE_PROTO_RANDOM		(1 << 9)
#define R_OVS_CT_NAT_RANGE_PERSISTENT		(1 << 10)
#define R_OVS_CT_NAT_RANGE_PROTO_RANDOM_FULLY	(1 << 11)

struct exec_ct {
	u32 flags;
	u16 zone_id;
	union {
		u32 min_addr4;
		u128 min_addr6;
	};
	union {
		u32 max_addr4;
		u128 max_addr6;
	};
	u16 min_port;
	u16 max_port;
} __attribute__((packed));

static __always_inline void fill_nat(struct ovs_conntrack_info *info,
				     struct exec_ct *ct)
{
	if (info->nat & OVS_CT_SRC_NAT)
		ct->flags |= R_OVS_CT_NAT_SRC;

	if (info->nat & OVS_CT_DST_NAT)
		ct->flags |= R_OVS_CT_NAT_DST;

	if (info->nat & NF_NAT_RANGE_PERSISTENT)
		ct->flags |= R_OVS_CT_NAT_RANGE_PERSISTENT;

	if (info->nat & NF_NAT_RANGE_PROTO_RANDOM)
		ct->flags |= R_OVS_CT_NAT_RANGE_PROTO_RANDOM;

	if (info->nat & NF_NAT_RANGE_PROTO_RANDOM_FULLY)
		ct->flags |= R_OVS_CT_NAT_RANGE_PROTO_RANDOM_FULLY;

	if (info->range.flags & NF_NAT_RANGE_MAP_IPS) {
		ct->flags |= R_OVS_CT_NAT_RANGE_MAP_IPS;
		if (info->family == NFPROTO_IPV4) {
			bpf_probe_read_kernel(&ct->min_addr4,
					      sizeof(ct->min_addr4),
					      &info->range.min_addr.ip);
			bpf_probe_read_kernel(&ct->max_addr4,
					      sizeof(ct->max_addr4),
					      &info->range.max_addr.ip);
		} else if (info->family == NFPROTO_IPV6) {
			bpf_probe_read_kernel(&ct->min_addr6,
					      sizeof(ct->min_addr6),
					      &info->range.min_addr.in6);
			bpf_probe_read_kernel(&ct->max_addr6,
					      sizeof(ct->max_addr6),
					      &info->range.max_addr.in6);
		}
	}

	if (info->range.flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		ct->flags |= R_OVS_CT_NAT_RANGE_PROTO_SPECIFIED;
		bpf_probe_read_kernel(&ct->min_port, sizeof(ct->min_port),
				      &info->range.min_proto.all);
		bpf_probe_read_kernel(&ct->max_port, sizeof(ct->max_port),
				      &info->range.max_proto.all);
	}
}

/* Hook for ovs_do_execute_action tracepoint. */
DEFINE_HOOK_RAW(
	struct nlattr *attr;
	struct sw_flow_key *key;
	struct exec_event *exec;
	struct execute_actions_ctx *ectx;
	u64 tid = bpf_get_current_pid_tgid();

	key = (struct sw_flow_key *) ctx->regs.reg[2];
	if (!key)
		return 0;

	attr = (struct nlattr *) ctx->regs.reg[3];
	if (!attr)
		return 0;

	ectx = bpf_map_lookup_elem(&inflight_exec, &tid);
	/* Filtering is done at the ovs_execute_actions kprobe. */
	if (!ectx)
		return 0;

	exec = get_event_section(event, COLLECTOR_OVS, OVS_DP_ACTION,
				 sizeof(*exec));
	if (!exec)
		return 0;

	exec->action = nla_type(attr);
	exec->recirc_id = BPF_CORE_READ(key, recirc_id);
	/* Do not emit tracking information if it's not a flow_exec action. */
	if (ectx->command) {
		struct exec_track_event *track =
			get_event_section(event, COLLECTOR_OVS,
					  OVS_DP_ACTION_TRACK, sizeof(*track));
		if (!track)
			return 0;

		track->queue_id = ectx->queue_id;
	}

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
	case OVS_ACTION_ATTR_RECIRC:
		{
		struct exec_recirc *recirc =
			get_event_section(event, COLLECTOR_OVS,
					  OVS_DP_ACTION_RECIRC,
					  sizeof(*recirc));
		if (!recirc)
			return 0;

		bpf_probe_read_kernel(&recirc->id, sizeof(recirc->id),
				      nla_data(attr));
		break;
		}
	case OVS_ACTION_ATTR_CT:
		{
		struct ovs_conntrack_info info;
		bpf_probe_read_kernel(&info, sizeof(info), nla_data(attr));

		struct exec_ct *ct=
			get_event_section(event, COLLECTOR_OVS,
					  OVS_DP_ACTION_CONNTRACK,
					  sizeof(*ct));
		if (!ct)
			return 0;

		ct->zone_id = info.zone.id;
		ct->flags = 0;

		if (info.commit)
			ct->flags |= R_OVS_CT_COMMIT;
		if (info.force)
			ct->flags |= R_OVS_CT_FORCE;

		if (info.family == NFPROTO_IPV4)
			ct->flags |= R_OVS_CT_IP4;
		else if (info.family == NFPROTO_IPV6)
			ct->flags |= R_OVS_CT_IP6;

		if (info.nat) {
			ct->flags |= R_OVS_CT_NAT;
			fill_nat(&info, ct);
		}
		break;
		}
	}

	return 0;
)

char __license[] SEC("license") = "GPL";
