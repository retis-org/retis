#include <common.h>
#include <ovs_common.h>

/* Hook for kprobe:ovs_packet_cmd_execute. */
DEFINE_HOOK_RAW(
	u64 tid = bpf_get_current_pid_tgid();
	u32 zero = 0;

	/* Place a dummy value in the inflight_exec_cmd map to indicate that
	 * a command execution is going on. */
	if (!bpf_map_update_elem(&inflight_exec_cmd, &tid, &zero, BPF_ANY)) {
		return -1;
	}
	return 0;
)

char __license[] SEC("license") = "GPL";
