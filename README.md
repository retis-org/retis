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
Collector(s) started: nft, skb, ct, skb-tracking, skb-drop
No probe(s) given: using tp:net:netif_receive_skb, tp:net:net_dev_start_xmit
7 probe(s) loaded

6034438235097 (9) [ping] 22026 [tp] net:net_dev_start_xmit #57d008c23d9ffff93bc8e6a6580 (skb ffff93bc8fe2f700)
  if 4 (wlp82s0) [redacted] > 2606:4700:4700::1111 ttl 64 label 0x87f1c len 64 proto ICMPv6 (58) type 128 code 0

6034449727598 (5) [irq/185-iwlwifi] 1359 [tp] net:netif_receive_skb #57d013b806effff93bc8b645180 (skb ffff93bc81f0d300)
  if 4 (wlp82s0) 2606:4700:4700::1111 > [redacted] ttl 54 label 0x9f52e len 64 proto ICMPv6 (58) type 129 code 0
```

The output is described in the [official
documentation](https://retis.readthedocs.io/en/stable/).

More advanced collections can be performed by providing more probes and by
adding filtering rules. For example one can use the [generic
profile](retis/profiles/generic.yaml) which defines a bigger set of probes.

```
$ retis -p generic collect -f 'udp port 53 and host 2606:4700:4700::1111'
L2+L3 packet filter(s) loaded
29 probe(s) loaded

6464781565852 (10) [isc-net-0000] 22818/22819 [k] ip6_output #5e133023f9cffff93bc85f28a00 (skb ffff93bc8148b000)
  [redacted].60578 > 2606:4700:4700::1111.53 ttl 64 label 0x116de len 59 proto UDP (17) len 51

6464781577262 (10) [isc-net-0000] 22818/22819 [tp] net:net_dev_queue #5e133023f9cffff93bc85f28a00 (skb ffff93bc8148b000)
  if 4 (wlp82s0) [redacted].60578 > 2606:4700:4700::1111.53 ttl 64 label 0x116de len 59 proto UDP (17) len 51

6464781579859 (10) [isc-net-0000] 22818/22819 [tp] net:net_dev_start_xmit #5e133023f9cffff93bc85f28a00 (skb ffff93bc8148b000)
  if 4 (wlp82s0) [redacted].60578 > 2606:4700:4700::1111.53 ttl 64 label 0x116de len 59 proto UDP (17) len 51

6464794631087 (11) [irq/191-iwlwifi] 1365 [tp] net:napi_gro_receive_entry #5e133c99bafffff93bc89dd4000 (skb ffff93bfd77f9f00)
  if 4 (wlp82s0) 2606:4700:4700::1111.53 > [redacted].60578 ttl 54 label 0xfacb2 len 79 proto UDP (17) len 71

6464794636532 (11) [irq/191-iwlwifi] 1365 [k] udp6_gro_receive #5e133c99bafffff93bc89dd4000 (skb ffff93bfd77f9f00)
  if 4 (wlp82s0) 2606:4700:4700::1111.53 > [redacted].60578 ttl 54 label 0xfacb2 len 79 proto UDP (17) len 71

6464794638402 (11) [irq/191-iwlwifi] 1365 [k] udp_gro_receive #5e133c99bafffff93bc89dd4000 (skb ffff93bfd77f9f00)
  if 4 (wlp82s0) 2606:4700:4700::1111.53 > [redacted].60578 ttl 54 label 0xfacb2 len 79 proto UDP (17) len 71

6464794640624 (11) [irq/191-iwlwifi] 1365 [tp] net:netif_receive_skb #5e133c99bafffff93bc89dd4000 (skb ffff93bfd77f9f00)
  if 4 (wlp82s0) 2606:4700:4700::1111.53 > [redacted].60578 ttl 54 label 0xfacb2 len 79 proto UDP (17) len 71

6464794657429 (11) [irq/191-iwlwifi] 1365 [k] udpv6_rcv #5e133c99bafffff93bc89dd4000 (skb ffff93bfd77f9f00)
  if 4 (wlp82s0) rxif 4 2606:4700:4700::1111.53 > [redacted].60578 ttl 54 label 0xfacb2 len 79 proto UDP (17) len 71
```

When storing events for later post-processing, the packets' journeys can be
reconstructed:

```
$ retis -p generic collect -f 'udp port 53 and host 2606:4700:4700::1111' -o \
      --cmd 'dig redhat.com @2606:4700:4700::1111'
$ retis sort
6946866196800 (11) [isc-net-0000] 23898/23899 [k] ip6_output #651717df140ffff93bc89dd7c00 (skb ffff93bc8c491500) n 0
  [redacted].54205 > 2606:4700:4700::1111.53 ttl 64 label 0x86973 len 59 proto UDP (17) len 51
  ↳ 6946866208851 (11) [isc-net-0000] 23898/23899 [tp] net:net_dev_queue #651717df140ffff93bc89dd7c00 (skb ffff93bc8c491500) n 1
      if 4 (wlp82s0) [redacted].54205 > 2606:4700:4700::1111.53 ttl 64 label 0x86973 len 59 proto UDP (17) len 51
  ↳ 6946866211760 (11) [isc-net-0000] 23898/23899 [tp] net:net_dev_start_xmit #651717df140ffff93bc89dd7c00 (skb ffff93bc8c491500) n 2
      if 4 (wlp82s0) [redacted].54205 > 2606:4700:4700::1111.53 ttl 64 label 0x86973 len 59 proto UDP (17) len 51

6946876837639 (7) [irq/187-iwlwifi] 1361 [tp] net:napi_gro_receive_entry #65172204f07ffff93bc93bf6580 (skb ffff93c01ebd8f00) n 0
  if 4 (wlp82s0) 2606:4700:4700::1111.53 > [redacted].54205 ttl 54 label 0x7ff08 len 79 proto UDP (17) len 71
  ↳ 6946876842090 (7) [irq/187-iwlwifi] 1361 [k] udp6_gro_receive #65172204f07ffff93bc93bf6580 (skb ffff93c01ebd8f00) n 1
      if 4 (wlp82s0) 2606:4700:4700::1111.53 > [redacted].54205 ttl 54 label 0x7ff08 len 79 proto UDP (17) len 71
  ↳ 6946876843587 (7) [irq/187-iwlwifi] 1361 [k] udp_gro_receive #65172204f07ffff93bc93bf6580 (skb ffff93c01ebd8f00) n 2
      if 4 (wlp82s0) 2606:4700:4700::1111.53 > [redacted].54205 ttl 54 label 0x7ff08 len 79 proto UDP (17) len 71
  ↳ 6946876845210 (7) [irq/187-iwlwifi] 1361 [tp] net:netif_receive_skb #65172204f07ffff93bc93bf6580 (skb ffff93c01ebd8f00) n 3
      if 4 (wlp82s0) 2606:4700:4700::1111.53 > [redacted].54205 ttl 54 label 0x7ff08 len 79 proto UDP (17) len 71
  ↳ 6946876855603 (7) [irq/187-iwlwifi] 1361 [k] udpv6_rcv #65172204f07ffff93bc93bf6580 (skb ffff93c01ebd8f00) n 4
      if 4 (wlp82s0) rxif 4 2606:4700:4700::1111.53 > [redacted].54205 ttl 54 label 0x7ff08 len 79 proto UDP (17) len 71
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
