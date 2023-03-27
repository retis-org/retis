#include <vmlinux.h>

#include <user_common.h>
#include <ovs_operation.h>

/* Hook for usdt:dpif_netlink_operate__::op_flow_execute. */
DEFINE_USDT_HOOK (
	int res;
	struct ovs_operation_event *exec_event =
		get_event_zsection(event, COLLECTOR_OVS, OVS_OPERATION,
				   sizeof(*exec_event));
	if (!exec_event)
		return 0;

	exec_event->type = OVS_OP_EXEC;

	return batch_process_op(OVS_OP_EXEC, exec_event);
)

char __license[] SEC("license") = "GPL";
