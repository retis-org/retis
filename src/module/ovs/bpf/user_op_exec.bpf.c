#include <vmlinux.h>

#include <user_common.h>
#include <ovs_operation.h>

/* Hook for usdt:dpif_netlink_operate__::op_flow_execute. */
DEFINE_USDT_HOOK (
	return batch_process_op(OVS_OP_EXEC, event);
)

char __license[] SEC("license") = "GPL";
