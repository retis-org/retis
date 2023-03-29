#include <vmlinux.h>

#include <user_common.h>
#include <ovs_operation.h>

/* Hook for usdt:dpif_netlink_operate__::op_flow_put. */
DEFINE_USDT_HOOK (
	int res;
	struct ovs_operation_event *put_event =
		get_event_zsection(event, COLLECTOR_OVS, OVS_OPERATION,
				   sizeof(*put_event));
	if (!put_event)
		return 0;

	put_event->type = OVS_OP_PUT;

	return batch_process_op(OVS_OP_PUT, put_event);
)

char __license[] SEC("license") = "GPL";
