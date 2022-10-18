#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("raw_tracepoint/probe")
int probe_raw_tracepoint(struct bpf_raw_tracepoint_args *ctx)
{
	return 0;
}

char __license[] SEC("license") = "GPL";
