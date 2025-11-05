# Collectors

Collectors are optional data retrievers and event section producers used in the
collection mode (the `collect` sub-command). They are responsible of handling
specific data (eg. `skb`) or logical parts of the stack (eg. `ct`).

The set of collectors to use is controlled by the `--collectors` argument. If
collectors are explicitly requested they become mandatory. If the `auto` special
key work is used (this is the default value), all collectors are started if
their prerequisites are met. Both `auto` and explicit collectors can be mixed,
in which case some collectors will be required while others used only if their
prerequisites are met. Setting `--collectors skb,auto` will require the `skb`
collector to start and make Retis to fail otherwise, while allowing for example
to put the `ovs` collector aside if Open vSwitch is not used on the target
machine.

The event sections produced by collectors do not always map 1 to 1 and are
documented in their [own section](../events/intro.md).

All available collectors are documented below. They can have collector-specific
arguments to the `collect` sub-command, which are documented too.

## Skb

The `skb` collector provides insights into the `struct sk_buff` (we call
instances of this `skb` below) kernel data structure, which holds metadata and
data for networking packets.

The `skb` collector does not install any probe itself, and is only responsible
for gathering data whenever an `skb` is available in a probe arguments. This is
done automatically. Eg. if the `skb` collector is enabled and a probe is added
(manually, by a profile or by another collector) on `kfree_skb_reason`, the
`skb` collector will generate events with data coming from the `skb` given as an
argument to the `kfree_skb_reason` function.

The `skb` collector has a single specific argument, `--skb-sections`. This is
used to choose which parts of the `skb` metadata to retrieve and
export in the events. See the `retis collect --help` for a detailed description.

The `skb` collector produces the [skb](../events/skb.md) and
[packet](../events/packet.md) event sections.

## Skb tracking

The `skb-tracking` collector does not track itself `skb` in the kernel (this is
done in the core) but allows to report the tracking information in the events.
This tracking information, which is basically a unique "id", can be used at
post-processing time to reconstruct in-kernel packets flow using the `sort`
post-processing command.

The `skb-tracking` collector produces the
[skb-tracking](../events/skb_tracking.md) event section.

## Skb drop

The `skb-drop` collector provides information about why an skb was dropped. This
collector acts on the `enum skb_drop_reason` values, although it also
understands non-core drop reasons such as `enum ovs_drop_reason`. The `skb-drop`
collector also adds a probe on the `skb:kfree_skb` tracepoint.

The `skb-drop` collector produces the [skb-drop](../events/skb_drop.md) event
section.

## Open vSwitch (ovs)

The `ovs` collector retrieves
[OpenVSwitch](https://www.openvswitch.org/)-specific data and can help tracking
packets in the userspace part. See the [dedicated documentation
page](ovs.md) for more details.

The `ovs` collector produces the [ovs](ovs.md) event section.

## Conntrack

The `ct` collector reports information collected from socket buffers
(`struct sk_buff`) about their conntrack status. This is done by reading the
`_nfct` field of an `skb`.

The reported information in the events contains conntrack status and protocol
specific data. Currently supported protocols are IPv4/6, TCP, UDP and ICMP.

The `ct` collector produces the [ct](../events/ct.md) event section.

## Netfilter

The `nft` collector provides insight into Netfilter rules and actions, by
automatically adding a probe on `__nft_trace_packet`. For the `nft` collector to
work a special dummy `nft` table must be added:

```none
table inet Retis_Table {
    chain Retis_Chain {
        meta nftrace set 1
    }
}
```

Retis can also install and uninstall the above table automatically by using the
`--allow-system-changes` cli parameter.

The `nft` collector has a single specific argument, `--nft-verdicts`. It is used
to choose which Netfilter verdicts will be reported in events. By default it
reports only `drop` and `accept` verdicts.

The `nft` collector produces the [nft](../events/nft.md) event section.

## Network device

The `dev` collector provides information about network devices, either if a
`struct net_device` is available as part of a probe arguments or through a
`struct sk_buff` and its reference.

The `dev` collector produces the [dev](../events/dev.md) event section.

## Namespace

The `ns` collector retrieves information about namespaces, currently only
network namespaces.

The `ns` collector produces the [netns](../events/netns.md) event section.

## Sock

The `sock` collector retrieves information about sockets.

The `sock` collector produces the [sock](..events/sock.md) event section.
