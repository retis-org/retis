/* Of course we need a common include dir */
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <common.h>

SEC("ext/hook")
int hook(struct trace_context *ctx, struct event *event)
{
	return 0;
}

char __license[] SEC("license") = "GPL";
