# Profiles

## Generic

The `generic` profile aims to provide a starting point for investigating
packets in the networking stack. It defines a wide set of probes in various
places and enables the `skb`, `skb-drop` and `skb-tracking` collectors.

```none
$ retis -p generic collect
```

## Ifdump

Collect packets just after the device driver in ingress and right before the
device driver in egress. This is similar to many well known packet capture
utilities (they use `AF_PACKET`).

```none
$ retis -p ifdump collect
7129250251406 (5) [ping] 23561 [tp] net:net_dev_start_xmit #67be86dc28effff8f67ed249b80 (skb ffff8f67919c2b00)
  if 4 (wlp82s0) [redacted] > 2606:4700:4700::1111 ttl 64 label 0xbf87b len 64 proto ICMPv6 (58) type 128 code 0

7129262331018 (0) [irq/185-iwlwifi] 1259 [tp] net:netif_receive_skb #67be926148affff8f6546b13700 (skb ffff8f6851bffd00)
  if 4 (wlp82s0) 2606:4700:4700::1111 > [redacted] ttl 54 label 0x55519 len 64 proto ICMPv6 (58) type 129 code 0
```

## Dropmon

Drop monitor profile, reporting packets being dropped including a stack trace to
have a hint on what were those packet flows in the stack.

```none
$ retis -p dropmon collect
4152973315243 [nc] 14839 [tp] skb:kfree_skb drop (NO_SOCKET)
    bpf_prog_88089ccd9794be3a_sd_devices+0x3601
    bpf_prog_88089ccd9794be3a_sd_devices+0x3601
    bpf_trace_run3+0x52
    kfree_skb_reason+0x8f
    tcp_v6_rcv+0x77
    ip6_protocol_deliver_rcu+0x6b
    ip6_input_finish+0x43
    __netif_receive_skb_one_core+0x62
    process_backlog+0x85
    __napi_poll+0x28
    net_rx_action+0x2a4
    __do_softirq+0xd1
    do_softirq.part.0+0x3d
    __local_bh_enable_ip+0x68
    __dev_queue_xmit+0x28b
    ip6_finish_output2+0x2ae
    ip6_finish_output+0x160
    ip6_xmit+0x2c0
    inet6_csk_xmit+0xe9
    __tcp_transmit_skb+0x535
    tcp_connect+0xb95
    tcp_v6_connect+0x515
    __inet_stream_connect+0x10f
    inet_stream_connect+0x3a
    __sys_connect+0xa8
    __x64_sys_connect+0x18
    do_syscall_64+0x5d
    entry_SYSCALL_64_after_hwframe+0x6e
  if 1 (lo) rxif 1 ::1.36986 > ::1.8080 ttl 64 label 0x975b1 len 40 proto TCP (6) flags [S] seq 2899194670 win 65476
```

## Nft dropmon

Similar to the above `dropmon` profile, but for netfilter drops.

```none
$ retis -p nft-dropmon collect --allow-system-changes
4 probe(s) loaded

3443313082998 [swapper/0] 0 [k] __nft_trace_packet
    __nft_trace_packet+0x1
    nft_do_chain+0x3ef
    nft_do_chain_inet+0x54
    nf_hook_slow+0x42
    ip_local_deliver+0xd0
    ip_sublist_rcv_finish+0x7e
    ip_sublist_rcv+0x186
    ip_list_rcv+0x13d
    __netif_receive_skb_list_core+0x29d
    netif_receive_skb_list_internal+0x1d1
    napi_complete_done+0x72
    virtnet_poll+0x3ce
    __napi_poll+0x28
    net_rx_action+0x2a4
    __do_softirq+0xd1
    __irq_exit_rcu+0xbe
    common_interrupt+0x86
    asm_common_interrupt+0x26
    pv_native_safe_halt+0xf
    default_idle+0x9
    default_idle_call+0x2c
    do_idle+0x226
    cpu_startup_entry+0x1d
    __pfx_kernel_init+0x0
    arch_call_rest_init+0xe
    start_kernel+0x71e
    x86_64_start_reservations+0x18
    x86_64_start_kernel+0x96
    __pfx_verify_cpu+0x0
  if 2 (eth0) rxif 2 172.16.42.1.52294 > 172.16.42.2.8080 ttl 64 tos 0x0 id 37968 off 0 [DF] len 60 proto TCP (6) flags [S] seq 1971640626 win 64240
  table firewalld (1) chain filter_IN_FedoraServer (202) handle 215 drop
...
$ nft -a list table inet firewalld
...
	chain filter_IN_FedoraServer { # handle 202
...
		jump filter_INPUT_POLICIES_post # handle 214
		meta l4proto { icmp, ipv6-icmp } accept # handle 273
		reject with icmpx admin-prohibited # handle 215         <- This one
	}
...
```

## Pcap

Profile enabling a set of options to collect events for later post-processing
conversion into the `pcap-ng` format using the `pcap` sub-command.

```none
$ retis -p pcap collect ...
$ retis -p pcap,generic collect
```
