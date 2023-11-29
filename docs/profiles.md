# Profiles

## Generic

The `generic` profile aims at providing a starting point for investigating
packets in the networking stack. It defines a wide set of probes in various
places and enables the `skb`, `skb-drop` and `skb-tracking` collectors.

```none
$ retis -p generic collect
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
$ retis -p nft-dropmon collect
```

## Pcap

Profile enabling a set of options to collect events for later post-processing
conversion into the `pcap-ng` format using the `pcap` sub-command.

```none
$ retis -p pcap collect ...
$ retis -p pcap,generic collect
```
