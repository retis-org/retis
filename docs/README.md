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

See `retis collect --help` for a description of each collector and its command
line arguments.

[^1]: Probes for tracking packets are always installed by the core.

## Post-processing

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

## Profiles and customization

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
[example profile](https://github.com/retis-org/retis/blob/main/test_data/profiles/example.yaml)
with inlined comments. If a profile is generic enough, consider contributing it!

## Filtering

Tracing packets can generate a lot of events, some of which are not interesting.
Retis implements a filtering logic to only report packets matching the filter or
being tracked (see [tracking](#tracking)).

Retis uses a pcap-filter syntax. See `man pcap-filter` for an overview on the
syntax.

```
$ retis collect -f 'tcp port 443'
...
```

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
   [in the sources](https://github.com/retis-org/retis/blob/main/src/core/tracking/skb_tracking.rs).

2. A collector, `skb-tracking`, retrieves the core tracking information (unique
   identifier and socket buffer address) and reports it in the event. Without
   enabling this collector, skb tracking information won't be reported and can't
   be used at post-processing time.

3. The `ovs` collector tracks packets in upcalls so we can follow a packet
   being sent to the OpenVSwitch user-space daemon, even if it is re-injected
   later on.
