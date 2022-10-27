#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/probe")
int probe_kprobe(struct pt_regs *ctx)
{
	return 0;
}

char __license[] SEC("license") = "GPL";
