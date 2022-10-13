/* Of course we need a common include dir */
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <common.h>

SEC("ext/hook")
int hook(struct trace_context *ctx, struct event *event)
{
	struct sk_buff *skb;
	unsigned char *pos;
	struct ethhdr eth;

	/* Let the verifier be happy */
	if (!ctx || !event)
		return 0;

	skb = get_skb(ctx);
	if (!skb)
		return 0;

	pos = BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, mac_header);
	bpf_probe_read_kernel(&eth, sizeof(struct ethhdr), pos);

	event->skb_etype = bpf_ntohs(eth.h_proto);

	return 0;
}

char __license[] SEC("license") = "GPL";
