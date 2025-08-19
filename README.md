# Retis

Tracing (filtered) packets in the [Linux](https://kernel.org) networking stack,
using [eBPF](https://ebpf.io) probes and interfacing with control and data paths
such as [OvS](https://www.openvswitch.org) or [Netfilter](https://netfilter.org).

Visit the [online documentation](https://retis.readthedocs.io) for more
details, or run `retis --help` and `retis <command> --help`.

![demo](demo.gif)

## Installation

Retis can be used as a container image, installed on supported distributions or
built from sources. All details on the [official
documentation](https://retis.readthedocs.io/en/stable/install/).

## Use cases

Retis aims at providing better visibility on complex single-host topologies and
linking useful context. It it designed to be modular in terms of what kind of
data is retrieved and where it is retrieved from. Retis can be used for
debugging networking issues, exploring the Linux networking stack or for testing
features (eg. in a CI script).

A few key points:

- Operates on "skb-enabled" functions and tracepoints.
- Offers filtering and tracking (the same packet can be seen multiple times,
  modified, etc) capabilities.
- Can retrieve more than the packet itself: additional metadata and contextual
  information.
- Does not require compilation on the target.
- Has post-processing abilities (eg. reconstructing a packet journey).
- Tries to have sane defaults.

Collecting packet events going in and out network devices (similarly to
well-known `AF_PACKET` existing utilities) can be as simple as:

```
$ retis collect
Collector(s) started: ct, nft, dev, skb, skb-drop, skb-tracking, ns
No probe(s) given: using tp:net:netif_receive_skb, tp:net:net_dev_start_xmit
7 probe(s) loaded

10041392747167 (9) [ping] 23932 [tp] net:net_dev_start_xmit #921f1a5d29fffff8ca2dd79f440 (skb ffff8ca30bbc3100)
  [redacted] > 2606:4700:4700::1111 ttl 64 label 0x18000 len 64 proto ICMPv6 (58) type 128 code 0
  ns 0x1/4026531840 if 4 (wlp82s0)

10041404857427 (0) [irq/177-iwlwifi] 1907 [tp] net:netif_receive_skb #921f25e9c53ffff8ca1c2e62100 (skb ffff8ca00f09f500)
  2606:4700:4700::1111 > [redacted] ttl 54 label 0xb57aa len 64 proto ICMPv6 (58) type 129 code 0
  ns 0x1/4026531840 if 4 (wlp82s0)
```

The output is described in the [official
documentation](https://retis.readthedocs.io/en/stable/).

More advanced collections can be performed by providing more probes and by
adding filtering rules. For example one can use the [generic
profile](retis/profiles/generic.yaml) which defines a bigger set of probes.

```
$ retis -p generic collect -f 'udp port 53 and host 2606:4700:4700::1111'
L2+L3 packet filter(s) loaded
30 probe(s) loaded

12313349514683 (1) [isc-net-0000] 26822/26823 [k] ip6_output #b32ecd2e5bbffff8ca00f0c6100 (skb ffff8ca396cf4600)
  [redacted].43366 > 2606:4700:4700::1111.53 ttl 64 label 0x10c7e len 59 proto UDP (17) len 51
  ns 0x1/4026531840
  ct_state NEW status 0x100 udp orig [[redacted].43366 > 2606:4700:4700::1111.53] reply [2606:4700:4700::1111.53 > [redacted].43366] zone 0 mark 0

12313349527752 (1) [isc-net-0000] 26822/26823 [tp] net:net_dev_queue #b32ecd2e5bbffff8ca00f0c6100 (skb ffff8ca396cf4600)
  [redacted].43366 > 2606:4700:4700::1111.53 ttl 64 label 0x10c7e len 59 proto UDP (17) len 51
  ns 0x1/4026531840 if 4 (wlp82s0)
  ct_state NEW status 0x188 udp orig [[redacted].43366 > 2606:4700:4700::1111.53] reply [2606:4700:4700::1111.53 > [redacted].43366] zone 0 mark 0

12313349531477 (1) [isc-net-0000] 26822/26823 [tp] net:net_dev_start_xmit #b32ecd2e5bbffff8ca00f0c6100 (skb ffff8ca396cf4600)
  [redacted].43366 > 2606:4700:4700::1111.53 ttl 64 label 0x10c7e len 59 proto UDP (17) len 51
  ns 0x1/4026531840 if 4 (wlp82s0)
  ct_state NEW status 0x188 udp orig [[redacted].43366 > 2606:4700:4700::1111.53] reply [2606:4700:4700::1111.53 > [redacted].43366] zone 0 mark 0

12313364132752 (4) [irq/181-iwlwifi] 1911 [tp] net:napi_gro_receive_entry #b32edb1f390ffff8ca3036e3c80 (skb ffff8ca325f87900)
  2606:4700:4700::1111.53 > [redacted].43366 ttl 54 label 0xfe6f0 len 79 proto UDP (17) len 71
  ns 0x1/4026531840 if 4 (wlp82s0)

12313364139400 (4) [irq/181-iwlwifi] 1911 [k] udp6_gro_receive #b32edb1f390ffff8ca3036e3c80 (skb ffff8ca325f87900)
  2606:4700:4700::1111.53 > [redacted].43366 ttl 54 label 0xfe6f0 len 79 proto UDP (17) len 71
  ns 0x1/4026531840 if 4 (wlp82s0)

12313364141628 (4) [irq/181-iwlwifi] 1911 [k] udp_gro_receive #b32edb1f390ffff8ca3036e3c80 (skb ffff8ca325f87900)
  2606:4700:4700::1111.53 > [redacted].43366 ttl 54 label 0xfe6f0 len 79 proto UDP (17) len 71
  ns 0x1/4026531840 if 4 (wlp82s0)

12313364143661 (4) [irq/181-iwlwifi] 1911 [tp] net:netif_receive_skb #b32edb1f390ffff8ca3036e3c80 (skb ffff8ca325f87900)
  2606:4700:4700::1111.53 > [redacted].43366 ttl 54 label 0xfe6f0 len 79 proto UDP (17) len 71
  ns 0x1/4026531840 if 4 (wlp82s0)

12313364186036 (4) [irq/181-iwlwifi] 1911 [k] udpv6_rcv #b32edb1f390ffff8ca3036e3c80 (skb ffff8ca325f87900)
  2606:4700:4700::1111.53 > [redacted].43366 ttl 54 label 0xfe6f0 len 79 proto UDP (17) len 71
  ns 0x1/4026531840 if 4 (wlp82s0) rxif 4
  ct_state REPLY status 0x18a udp orig [[redacted].43366 > 2606:4700:4700::1111.53] reply [2606:4700:4700::1111.53 > [redacted].43366] zone 0 mark 0
```

When storing events for later post-processing, the packets' journeys can be
reconstructed:

```
$ retis -p generic collect -f 'udp port 53 and host 2606:4700:4700::1111' -o \
      --cmd 'dig redhat.com @2606:4700:4700::1111'
$ retis sort
12510323851756 (1) [isc-net-0000] 27137/27138 [k] ip6_output #b60c968c1ecffff8ca27999de40 (skb ffff8ca325f86100) n 0
  [redacted].46050 > 2606:4700:4700::1111.53 ttl 64 label 0xa92bf len 59 proto UDP (17) len 51
  ns 0x1/4026531840
  ct_state NEW status 0x100 udp orig [[redacted].46050 > 2606:4700:4700::1111.53] reply [2606:4700:4700::1111.53 > [redacted].46050] zone 0 mark 0
  ↳ 12510323863992 (1) [isc-net-0000] 27137/27138 [tp] net:net_dev_queue #b60c968c1ecffff8ca27999de40 (skb ffff8ca325f86100) n 1
      [redacted].46050 > 2606:4700:4700::1111.53 ttl 64 label 0xa92bf len 59 proto UDP (17) len 51
      ns 0x1/4026531840 if 4 (wlp82s0)
      ct_state NEW status 0x188 udp orig [[redacted].46050 > 2606:4700:4700::1111.53] reply [2606:4700:4700::1111.53 > [redacted].46050] zone 0 mark 0
  ↳ 12510323867976 (1) [isc-net-0000] 27137/27138 [tp] net:net_dev_start_xmit #b60c968c1ecffff8ca27999de40 (skb ffff8ca325f86100) n 2
      [redacted].46050 > 2606:4700:4700::1111.53 ttl 64 label 0xa92bf len 59 proto UDP (17) len 51
      ns 0x1/4026531840 if 4 (wlp82s0)
      ct_state NEW status 0x188 udp orig [[redacted].46050 > 2606:4700:4700::1111.53] reply [2606:4700:4700::1111.53 > [redacted].46050] zone 0 mark 0

12510336743330 (0) [irq/177-iwlwifi] 1907 [tp] net:napi_gro_receive_entry #b60ca2d77a2ffff8ca2fcc582c0 (skb ffff8ca303bd0c00) n 0
  2606:4700:4700::1111.53 > [redacted].46050 ttl 54 label 0xc8017 len 79 proto UDP (17) len 71
  ns 0x1/4026531840 if 4 (wlp82s0)
  ↳ 12510336748601 (0) [irq/177-iwlwifi] 1907 [k] udp6_gro_receive #b60ca2d77a2ffff8ca2fcc582c0 (skb ffff8ca303bd0c00) n 1
      2606:4700:4700::1111.53 > [redacted].46050 ttl 54 label 0xc8017 len 79 proto UDP (17) len 71
      ns 0x1/4026531840 if 4 (wlp82s0)
  ↳ 12510336750432 (0) [irq/177-iwlwifi] 1907 [k] udp_gro_receive #b60ca2d77a2ffff8ca2fcc582c0 (skb ffff8ca303bd0c00) n 2
      2606:4700:4700::1111.53 > [redacted].46050 ttl 54 label 0xc8017 len 79 proto UDP (17) len 71
      ns 0x1/4026531840 if 4 (wlp82s0)
  ↳ 12510336752512 (0) [irq/177-iwlwifi] 1907 [tp] net:netif_receive_skb #b60ca2d77a2ffff8ca2fcc582c0 (skb ffff8ca303bd0c00) n 3
      2606:4700:4700::1111.53 > [redacted].46050 ttl 54 label 0xc8017 len 79 proto UDP (17) len 71
      ns 0x1/4026531840 if 4 (wlp82s0)
  ↳ 12510336766269 (0) [irq/177-iwlwifi] 1907 [k] udpv6_rcv #b60ca2d77a2ffff8ca2fcc582c0 (skb ffff8ca303bd0c00) n 4
      2606:4700:4700::1111.53 > [redacted].46050 ttl 54 label 0xc8017 len 79 proto UDP (17) len 71
      ns 0x1/4026531840 if 4 (wlp82s0) rxif 4
      ct_state REPLY status 0x18a udp orig [[redacted].46050 > 2606:4700:4700::1111.53] reply [2606:4700:4700::1111.53 > [redacted].46050] zone 0 mark 0
```

Retis offers many more features including retrieving [conntrack
information](https://retis.readthedocs.io/en/stable/modules/ct/), [advanced
filtering](https://retis.readthedocs.io/en/stable/filtering/), [monitoring
dropped packets](https://retis.readthedocs.io/en/stable/profiles/#dropmon) and
[dropped packets from Netfilter](https://retis.readthedocs.io/en/stable/profiles/#nft-dropmon),
generating `pcap` files from the collected packets, allowing [writing
post-processing scripts in Python](https://retis.readthedocs.io/en/stable/python/)
and more.

## Contributing

Retis is under [GPL v2](retis/LICENSE) and welcomes contributions. See our
[contributing guide](https://retis.readthedocs.io/en/stable/CONTRIBUTING/) for
more details.
