#include <vmlinux.h>
#include <bpf/usdt.bpf.h>

#include <user_common.h>

DEFINE_USDT_HOOK (
	// Do nothing!!
    return 0;
)

char __license[] SEC("license") = "GPL";
