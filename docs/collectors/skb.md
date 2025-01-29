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
used to choose which parts of the `skb` metadata and/or data to retrieve and
export in the events. The raw start of the packet (headers), ARP, IPv4/6, TCP,
UDP and ICMPv4/v6 information are always included. See the `retis collect
--help` for a detailed description.

Display of link layer information is controlled by the `--print-ll` argument of
the `collect`, `print` and `sort` subcommands.

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

### Ethernet section

```none
{src mac} > {dst mac} ethertype {etype name} ({etype hex})
```

### VLAN section

```none
vlan (id {id} prio {prio} [drop] [accel])
```

### ARP section

```none
request who-has {ip} tell {ip}
```

or,

```none
reply {ip} is at {mac}
```

### IP section

For IPv4:

```none
{src ip}.{src port} > {dst ip}.{dst port} {ECN info} ttl {ttl} tos {tos} id {id}
    off {frag offset} [{flags}] len {packet len} proto {protocol name}
```

- `ECN info` can be one of `CE`, `ECT(0)` or `ECT(1)`.
- `flags` are constructed with a combination of `+`, `DF` and `rsvd`.

For IPv6:

```none
{src ip}.{src port} > {dst ip}.{dst port} {ECN info} ttl {ttl} label {flow label}
    len {packet len} proto {protocol name}
```

### TCP section

```none
flags [{flags}] seq {sequence} ack {acked sequence} win {window}
```

- `flags` are constructed using a combination of `F` (fin), `S` (syn), `R`
  (reset), `P` (push), `.` (ack), `U` (urgent).
- `sequence` can be a range (`{start}:{end}`) or a single number (`{sequence}`).

### UDP section

```none
len {UDP data len}
```

### ICMP & ICMPv6 sections

```none
type {type number} code {code number}
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
