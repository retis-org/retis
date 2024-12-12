# Retis - Tracing packets in the Linux networking stack & friends

Retis aims at improving visibility of what happens in the Linux networking stack
and different control and/or data paths, some of which can be in userspace. It
works either in a single collect & display phase, or in a collect then process
fashion.

## Event collection

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

```none
$ retis collect
Collector(s) started: skb-tracking, skb, skb-drop, ovs, nft, ct
5 probe(s) loaded
...
$ retis collect -c skb,skb-drop
4 probe(s) loaded
...
```

In order to allow post-processing, events need to be stored in a file. This is
done using the `-o` option (defaults to `retis.data`). To also output the events
to the console in parallel, one can use `--print`.

```none
$ retis collect -c skb,skb-drop,skb-tracking -o
4 probe(s) loaded
...
$ retis collect -c skb,skb-drop,skb-tracking -o --print
4 probe(s) loaded
...
```

### Collectors

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
| ct           | Conntrack info      | No              |

See `retis collect --help` for a description of each collector and its command
line arguments.

[^1]: Probes for tracking packets are always installed by the core.

## Filtering

Tracing packets can generate a lot of events, some of which are not
interesting.  Retis implements a filtering logic to only report
packets matching the filter or being tracked (see [tracking](#tracking)).
Retis has two ways of filtering and both can coexist.
One is based on the [packet content](filtering.md#packet), e.g.:

```none
$ retis collect -f 'arp or tcp port 443'
...
```

and the other is based on [metadata](filtering.md#metadata), e.g.:

```none
$ retis collect -m 'sk_buff.dev.nd_net.net.ns.inum == 4026531840'
...
```

The [filtering](filtering.md) page provides a more detailed
explanation of their respective features, covering aspects such as how
to use different filter types, the specific syntax rules, and examples
of filters.

## Tracking

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
   [in the sources](https://github.com/retis-org/retis/blob/main/retis/src/core/tracking/skb_tracking.rs).

2. A collector, `skb-tracking`, retrieves the core tracking information (unique
   identifier and socket buffer address) and reports it in the event. Without
   enabling this collector, skb tracking information won't be reported and can't
   be used at post-processing time.

3. The `ovs` collector tracks packets in upcalls so we can follow a packet
   being sent to the OpenVSwitch user-space daemon, even if it is re-injected
   later on.

## Profiles and customization

Retis has the concept of profiles, which are a predefined set of cli arguments
(e.g. collectors for the `collect` command). Profiles are meant to improve user
experience to provide a comprehensive and consistent configuration to Retis
aimed at operating on pre-defined topics.

```none
$ retis -p generic collect
...
```

Available profiles can be listed using the `profile` command.

```none
$ retis profile list
...
```

Profiles can be extended by using cli arguments. Cli arguments can also be used
without a profile. One example is adding probes while collecting events.

```none
$ retis -p dropmon collect -p skb:consume_skb
...
$ retis collect -p skb:kfree_skb -p ovs_ct_clear
...
```

New profiles can be written and used if stored in `/etc/retis/profiles` or
`$HOME/.config/profiles`. Here is an
[example profile](https://github.com/retis-org/retis/blob/main/retis/test_data/profiles/example.yaml)
with inlined comments. If a profile is generic enough, consider contributing it!

## Post-processing

Events stored in a file can be formatted and displayed to the console using the
simple `print` command (the events filename used for the input defaults to
`retis.data`).

```none
$ retis print
...
```

But events can also be post-processed. Retis allows to trace packets across the
networking stack and as such the same packet can be seen multiple times (e.g. in
the IP stack, TCP stack, OvS stack & netfilter stack; sometimes multiple times
in each subsystem depending on which probes were loaded). The `sort` command
uses information reported by the `skb-tracking` and the `ovs` collectors to
identify unique packets and group/reorder the events so the same packet can be
efficiently tracked in the stack.

```none
$ retis collect --allow-system-changes -p ip_local_deliver \
        --nft-verdicts drop -f 'udp port 8080' -o --print
...
$ retis sort

3316376152002 [swapper/2] 0 [k] ip_local_deliver #304276b119fffff9847c36ba800 (skb 18446630032886128640) n 0
  if 2 (eth0) rxif 2 172.16.42.1.40532 > 172.16.42.2.8080 ttl 64 tos 0x0 id 14042 off 0 [DF] len 32 proto UDP (17) len 4
  + 3316376220653 [swapper/2] 0 [k] __nft_trace_packet #304276b119fffff9847c36ba800 (skb 18446630032886128640) n 1
    if 2 (eth0) rxif 2 172.16.42.1.40532 > 172.16.42.2.8080 ttl 64 tos 0x0 id 14042 off 0 [DF] len 32 proto UDP (17) len 4
    table firewalld (1) chain filter_IN_FedoraServer (202) handle 215 drop
  + 3316376224687 [swapper/2] 0 [tp] skb:kfree_skb #304276b119fffff9847c36ba800 (skb 18446630032886128640) n 2 drop (NETFILTER_DROP)
    if 2 (eth0) rxif 2 172.16.42.1.40532 > 172.16.42.2.8080 ttl 64 tos 0x0 id 14042 off 0 [DF] len 32 proto UDP (17) len 4
```

Another post-processing command, `pcap`, can be used to generate `pcap-ng` files
from a set of stored Retis events. For this to work the collection has to be
done using (at least) the `pcap` profile. For now `pcap-ng` files can be
generated by filtering the events using a single probe.

```none
$ retis -p pcap,generic collect -o
$ retis pcap --probe net:netif_receive_skb | tcpdump -nnr -
$ retis pcap --probe net:net_dev_start_xmit -o retis.pcap
$ wireshark retis.pcap
```

Some post-processing commands (eg. `print`, `sort`) can generate a long output.
In such case a pager is automatically used in case the output is larger than the
current terminal. By default `less` is used but the pager can be explicitly
chosen by setting the `PAGER` environment variable, or unset by setting
`NOPAGER`.

```none
$ PAGER=more retis sort
$ NOPAGER=1 retis sort
```

In addition to built-in post-processing commands, it is possible to use the
python bindings to implement custom processing. See the
[python bindings documentation](python.md).
