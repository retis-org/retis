# Retis

Tracing packets in the [Linux](https://kernel.org) networking stack, using
[eBPF](https://ebpf.io) and interfacing with control and data paths such as
[OvS](https://www.openvswitch.org) or [Netfilter](https://netfilter.org).

For bug reports, feature suggestions and contributions; please see the
[contributing guide](CONTRIBUTING.md) guide first. We also have a public IRC
channel on [Libera.chat](https://libera.chat):
[`#retis`](https://web.libera.chat/?channel=#retis).

![demo](demo.gif)

An overview and some examples can be found below, but note the `--help` flag
should document most of what Retis can do.

```
$ retis --help
...
$ retis <command> --help
...
```

### Table of contents

* [Overview](#overview)
  * [Event collection](#event-collection)
    * [Collectors](#collectors)
  * [Post processing](#post-processing)
  * [Profiles and customization](#profiles-and-customization)
  * [Filtering](#filtering)
  * [Tracking](#tracking)
  * [Simple copy/paste examples](#simple-copypaste-examples)
* [Limitations](#limitations)
* [Requirements](#requirements)
  * [Supported operating systems](#supported-operating-systems)
* [Installation](#installation)
  * [COPR](#copr)
  * [Container image](#container-image)
  * [From sources](#from-sources)
  * [Running as non-root](#running-as-non-root)

## Overview

Retis aims at improving visibility of what happens in the Linux networking stack
and different control and/or data paths, some of which can be in userspace. It
works either in a single collect & display phase, or in a collect then process
fashion.

### Event collection

The entry point for most of the use cases is the `collect` command, which will
install probes and gather events for instant reporting on the console or for
later processing writing events to a file (or both). In addition to
collect-level options, `retis collect` has the concept of collectors. Those
collectors can be enabled individually and will act on different parts of the
networking stack to retrieve specific information.

Currently supported collectors are [listed below](#collectors). By default Retis
will try to load all collectors if their individual requirements are met (e.g.
the `ovs` collector needs the OpenVSwitch kernel module to be loaded) but
collectors can be explicitly selected too (here if prerequisites are not met an
error will be returned). If no specific option is used, Retis will by default
output the events to the console.

```
$ retis collect
00:42:00 [INFO] Collector(s) started: skb-tracking, skb, skb-drop, ovs
00:42:01 [INFO] 5 probe(s) loaded
...
$ retis collect -c skb,skb-drop
00:42:00 [INFO] 4 probe(s) loaded
...
```

In order to allow post-processing, events need to be stored in a file. This is
done using the `-o` option. To also output the events to the console in
parallel, one can use `--print`.

```
$ retis collect -c skb,skb-drop,skb-tracking -o retis.data
00:42:00 [INFO] 4 probe(s) loaded
...
$ retis collect -c skb,skb-drop,skb-tracking -o retis.data --print
00:42:00 [INFO] 4 probe(s) loaded
...
```

#### Collectors

Collectors are responsible for filling events and target specific areas or data
types. Some, but not all, install specific probes to build their events.
Currently supported collectors are:

| Collector    | Data collected      | Installs probes |
| ------------ | ------------------- | --------------- |
| skb          | Packet information  | No              |
| skb-drop     | Drop reason         | Yes (1)         |
| skb-tracking | Packet tracking id  | No[^1]          |
| ovs          | OpenVSwitch data    | Yes (many)      |
| nft          | Nftables context    | Yes (1)         |

See `retis collect --help` for a description of each collector and its command
line arguments.

[^1]: Probes for tracking packets are always installed by the core.

### Post-processing

Events stored in a file can be formatted and displayed to the console using the
simple `print` command.

```
$ retis print retis.data
...
```

But events can also be post-processed. Retis allows to trace packets across the
networking stack and as such the same packet can be seen multiple times (e.g. in
the IP stack, TCP stack, OvS stack & netfilter stack; sometimes multiple times
in each subsystem depending on which probes where loaded). The `sort` command
uses information reported by the `skb-tracking` and the `ovs` collectors to
identify unique packets and group/reorder the events so the same packet can be
efficiently tracked in the stack.

```
$ retis collect --allow-system-changes -p kprobe:ip_local_deliver \
        --nft-verdicts drop -f 'udp port 8080' -o retis.data --print
...
$ retis sort retis.data

3316376152002 [swapper/2] 0 [k] ip_local_deliver #304276b119fffff9847c36ba800 (skb 18446630032886128640) n 0
  if 2 (eth0) rxif 2 172.16.42.1.40532 > 172.16.42.2.8080 ttl 64 tos 0x0 id 14042 off 0 [DF] len 32 proto UDP (17) len 4
  + 3316376220653 [swapper/2] 0 [k] __nft_trace_packet #304276b119fffff9847c36ba800 (skb 18446630032886128640) n 1
    if 2 (eth0) rxif 2 172.16.42.1.40532 > 172.16.42.2.8080 ttl 64 tos 0x0 id 14042 off 0 [DF] len 32 proto UDP (17) len 4
    table firewalld (1) chain filter_IN_FedoraServer (202) handle 215 drop
  + 3316376224687 [swapper/2] 0 [tp] skb:kfree_skb #304276b119fffff9847c36ba800 (skb 18446630032886128640) n 2 drop (NETFILTER_DROP)
    if 2 (eth0) rxif 2 172.16.42.1.40532 > 172.16.42.2.8080 ttl 64 tos 0x0 id 14042 off 0 [DF] len 32 proto UDP (17) len 4
```

### Profiles and customization

Retis has the concept of profiles, which are a predefined set of cli arguments
(e.g. collectors for the `collect` command). Profiles are meant to improve user
experience to provide a comprehensive and consistent configuration to Retis
aimed at operating on pre-defined topics.

```
$ retis -p generic collect
...
```

Available profiles can be listed using the `profile` command.

```
$ retis profile list
...
```

Profiles can be extended by using cli arguments. Cli arguments can also be used
without a profile. One example is adding probes while collecting events.

```
$ retis -p dropmon collect -p tp:skb:consume_skb
...
$ retis collect -p tp:skb:kfree_skb -p kprobe:ovs_ct_clear
...
```

New profiles can be written and used if stored in `/etc/retis/profiles` or
`$HOME/.config/profiles`. Here is an
[example profile](test_data/profiles/example.yaml) with inlined
comments. If a profile is generic enough, consider contributing it!

### Filtering

Tracing packets can generate a lot of events, some of which are not interesting.
Retis implements a filtering logic to only report packets matching the filter or
being tracked (see [tracking](#tracking)).

Retis uses a pcap-filter syntax. See `man pcap-filter` for an overview on the
syntax.

```
$ retis collect -f 'tcp port 443'
...
```

### Tracking

Retis does its best to track packets in the networking stack, and does it in
different ways. Note that tracking packets is not a built-in feature of the
Linux kernel and doing so is complex and cannot be 100% foolproof (but of course
bugs should be reported and fixed).

1. A Retis core built-in feature generates unique identifiers by tracking the
   data part of [socket buffers](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/skbuff.h?h=v6.3#n737).
   The socket buffer is also included in the identifier so we can track clones
   and friends. This core skb tracking logic is used by the filtering part for
   Retis to track packets after they were modified (e.g. NAT). Full details on
   the implementation can be found
   [in the sources](src/core/tracking/skb_tracking.rs).

2. A collector, `skb-tracking`, retrieves the core tracking information (unique
   identifier and socket buffer address) and reports it in the event. Without
   enabling this collector, skb tracking information won't be reported and can't
   be used at post-processing time.

3. The `ovs` collector tracks packets in upcalls so we can follow a packet
   being sent to the OpenVSwitch user-space daemon, even if it is re-injected
   later on.

### Simple copy/paste examples

Drop monitor-like, listing packets being dropped by the kernel with an
associated stack trace and drop reason (in the example below, no socket was
found).

```
$ retis -p dropmon collect
00:42:00 [INFO] 4 probe(s) loaded

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

Monitoring packets dropped by netfilter, the exact nft rule can be retrieved
using `nft -a list table ...`.

```
$ retis -p nft-dropmon collect --allow-system-changes
00:42:00 [INFO] 4 probe(s) loaded

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

## Limitations

Known and current limitations:

- By default Retis does not modify the system (e.g. load kernel modules, change
  the configuration, add a firewalling rule). This is done on purpose but might
  mean some prerequisites will be missing if not added manually. The only
  example for now is the `nft` module that requires a specific nft rule to be
  inserted. If that rule is not there, no nft event will be reported. To allow
  Retis to modify the system, use the `--allow-system-changes` option when
  running the `collect` command. See `retis collect --help` for further details
  about changes applied to the system.

- Retis operates mainly on `struct sk_buff` objects meaning a good part of
  locally generated traffic can't be traced at the moment. E.g. locally
  generated traffic from a container can be traced when it exits the container.

- Profiles combination might fail if flags are used multiple times or if some
  arguments are incompatible. Use with care.

Additional notes (not strictly limitations):

- Filtering & tracking packets being modified can only work if the packet is at
  least seen once in a form where it can be matched against the filter. E.g.
  tracking SNATed packets only in `skb:consume_skb` with a filter on the
  original address won't generate any event.

- Some fields present in the packet might not be reported when probes are early
  in the stack, while being shown in later ones. This is because Retis probes
  rely on the networking stack knowledge of the packet and if some parts weren't
  processed yet they can't be reported. E.g. TCP ports won't be reported from
  `kprobe:ip_rcv`.

## Requirements

All requirements are for commands collecting events, for now only `collect`.

Mandatory requirements:

- The kernel configuration must be available either in `/proc/config.gz` or in
  `/boot/config-$(uname -r)`.

- Retis needs `CAP_BPF` and access to all files listed in the
  [requirements](#requirements).

- The following kernel configuration:
  - `CONFIG_BPF_SYSCALL=y`.
  - `CONFIG_DEBUG_INFO_BTF=y` to parse kernel functions and types.

Not strictly required but best for user experience and feature scope:

- The following kernel configuration:
  - `CONFIG_KPROBES=y` to allow using kprobes.
  - `CONFIG_PERF_EVENTS=y` to retrieve stack traces (& probably more).

- `debugfs` mounted to `/sys/kernel/debug` to allow filtering functions and
  events.

- `/etc/os-release` to gather information about the current distribution.

### Supported operating systems

Those are operating systems we know are compatible with running Retis. Of course
the list is not exhaustive (let us know if we can add new lines).

| Operating system | Notes                                                |
| ---------------- | ---------------------------------------------------- |
| Fedora           | All officially supported versions including Rawhide  |
| RHEL9            |                                                      |
| CentOS Stream 9  |                                                      |
| RHEL8            | >= 8.6                                               |
| Ubuntu Jammy     |                                                      |

## Installation

Retis can be installed from [COPR](https://copr.fedorainfracloud.org/coprs/atenart/retis/)
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

The Retis container can also be run manually,

```
$ podman run --privileged --rm -it --pid=host \
      --cap-add SYS_ADMIN --cap-add BPF --cap-add SYSLOG \
      -v /sys/kernel/btf:/sys/kernel/btf:ro \
      -v /sys/kernel/debug:/sys/kernel/debug:ro \
      -v /boot/config-$(uname -r):/kconfig:ro \
      -v $(pwd):/data:rw \
      quay.io/retis/retis:latest --help
```

- Or using `docker` in place of `podman` in the above.

- When running on CoreOS, Fedora Silverblue and friends replace `-v
  /boot/config-$(uname -r):/kconfig:ro` with `-v /lib/modules/$(uname
  -r)/config:/kconfig:ro` in the above.

The `/data` container mount point is used to allow storing persistent data for
future use (e.g. logged events using the `-o` cli option).

### From sources

Retis depends on the following (in addition to Git and Cargo):
- rust >= 2021
- clang
- libelf
- libpcap
- llvm
- make
- pkg-config

On Fedora, one can run:

```
$ dnf -y install git cargo clang elfutils-libelf-devel \
        libpcap-devel llvm make pkgconf-pkg-config
```

On Ubuntu:

```
$ apt update
$ apt -y install git cargo clang libelf-dev libpcap-dev llvm make pkg-config
```

Then, to download and build Retis:

```
$ git clone --depth 1 https://github.com/retis-org/retis; cd retis
$ cargo build --release
$ ./target/release/retis --help
```

Finally, profiles should be installed in either `/etc/retis/profiles` or
`$HOME/.config/retis/profiles`.

```
$ mkdir -p /etc/retis/profiles
$ cp profiles/* /etc/retis/profiles
```

### Running as non-root

Retis can run as non-root if it has the right capabilities. Note that doing this
alone often means `debugfs` won't be available as it's usually owned by `root`
only and Retis won't be able to fully filter probes.

```
$ sudo setcap cap_sys_admin,cap_bpf,cap_syslog=ep $(which retis)
$ retis collect
```
