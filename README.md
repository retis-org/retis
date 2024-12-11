# Retis

Tracing packets in the [Linux](https://kernel.org) networking stack, using
[eBPF](https://ebpf.io) and interfacing with control and data paths such as
[OvS](https://www.openvswitch.org) or [Netfilter](https://netfilter.org).

Visit the [online documentation](https://retis.readthedocs.io) for more
details.


![demo](demo.gif)

## Quick start
An overview and some examples can be found in the
[Documentation](https://retis.readthedocs.io), but note the `--help` flag
should document most of what Retis can do.

```
$ retis --help
...
$ retis <command> --help
...
```

## Examples

### Drop monitoring
Listing packets being dropped by the kernel with an associated stack trace and drop reason
```
$ retis -p dropmon collect
4 probe(s) loaded

3392678938917 [nc] 2311 [tp] skb:kfree_skb drop (NO_SOCKET)
    bpf_prog_3a0ef5414c2f6fca_sd_devices+0xa0ad
    bpf_prog_3a0ef5414c2f6fca_sd_devices+0xa0ad
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
    do_softirq.part.0+0x5f
    __local_bh_enable_ip+0x68
    __dev_queue_xmit+0x293
    ip6_finish_output2+0x2a3
    ip6_finish_output+0x160
    ip6_xmit+0x2c0
    inet6_csk_xmit+0xe9
    __tcp_transmit_skb+0x534
    tcp_connect+0xaf6
    tcp_v6_connect+0x515
    __inet_stream_connect+0x103
    inet_stream_connect+0x3a
    __sys_connect+0xa8
    __x64_sys_connect+0x18
    do_syscall_64+0x5d
    entry_SYSCALL_64_after_hwframe+0x72
  if 1 (lo) rxif 1 ::1.60634 > ::1.80 ttl 64 label 0x9c404 len 40 proto TCP (6) flags [S] seq 3918324244 win 65476
...
```

### Monitoring packets dropped by netfilter
The exact nft rule can be retrieved using `nft -a list table ...`.

```
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

## Installation

Retis can be installed from [COPR](https://copr.fedorainfracloud.org/coprs/g/retis/retis/)
for rpm-compatible distributions, from a container image or from sources.

### COPR

RPM packages for Fedora (currently supported releases including Rawhide), RHEL (>=
8) and EPEL (>= 8) are available.

```
$ dnf -y copr enable @retis/retis
$ dnf -y install retis
$ retis --help
```

Or on older distributions,

```
$ yum -y copr enable @retis/retis
$ yum -y install retis
$ retis --help
```

### Container image

The preferred method to run Retis in a container is by using the provided
[retis_in_container.sh](tools/retis_in_container.sh) script,

```
$ curl -O https://raw.githubusercontent.com/retis-org/retis/main/tools/retis_in_container.sh
$ chmod +x retis_in_container.sh
$ ./retis_in_container.sh --help
```

### From sources
For details on how to build retis, visit the
[documentation](https://retis.readthedocs.io/en/stable/install/).
