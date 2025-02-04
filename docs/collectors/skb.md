# SKB collector

The `skb` collector provides insights into the `struct sk_buff` (we call
instances of this `skb` below) kernel data structure, which holds metadata and
data for networking packets.

The `skb` collector does not install any probe itself, and is only responsible
for gathering data whenever an `skb` is available in a probe arguments. This is
done automatically. Eg. if the `skb` collector is enabled and a probe is added
(manually, by a profile or by another collector) on `kfree_skb_reason`, the
`skb` collector will generate events with data coming from the `skb` given as an
argument to the `kfree_skb_reason` function.

## Arguments

The `skb` collector has a single specific argument, `--skb-sections`. This is
used to choose which parts of the `skb` metadata to retrieve and export in the
events. The raw start of the packet (headers) is always included. See the `retis
collect --help` for a detailed description.

When collecting event for later `pcap-ng` file generation (see `retis pcap
--help`), it's best to collect the `dev` and `ns` sections too.

## Events

Full `skb` collector events will be constructed with the following. Non-reported
or invalid fields are automatically hidden.

### Ns event section

```none
ns {namespace id}
```

### Net device event section

```none
if {interface index} ({interface name}) rxif {rx interface index}
```

### VLAN acceleration section

```none
vlan_accel (id {id} prio {prio} [drop])
```

### Metadata & dataref sections

Those two sections report metadata and reference counting from the socket buffer
itself.

```none
skb [{csum} hash {skb hash} data_len {skb data lenght} priority {skb priority}
    {flags} fclone {fast clone count} users {user count} dataref {skb refcount}]
```

- `csum` information, the format is slightly different depending on the checksum
  status (`none`, `unnecessary`, `partial` or `complete`).
- `flags` are a combination of `nohdr` and `cloned`.

### GSO section

Generic Segmentation Offload information linked to an `skb` (see
`skb_shared_info`).

```none
gso [type {GSO type} flags {GSO flags} frags {nr of GSO frags}
    segs {nr of GSO segs} size {GSO size}]
```

- `GSO type`, see `SKBFL_*` in the Linux kernel `include/linux/skbuff.h`.
- `GSO flags`, see `SKB_GSO_*` in the Linux kernel `include/linux/skbuff.h`.

### Packet section

The packet itself (payload) is printed on a dedicated line when using the
multi-line format and the output is coming from `tcpdump`.
