# Skb event

Full `skb` collector events will be constructed with the following. Non-reported
or invalid fields are automatically hidden.

When using the multi-line format the metadata is displayed on a line, followed
by information from the packet itself on a second dedicated line:

```none
{metadata info}
{packet info}
```

## Metadata info

### Ns event section

```none
ns [{unique id}/]{inum}
```

- `unique id` is a unique number provided by the kernel to help identifying
  network namespaces. It is guaranteed not to be reused. It might not be
  available on older kernels.

- `inum` is the inode number associated with a namespace and is unique while the
  namespace is in use. It can be reused after a namespace is deleted and because
  of this can't be used to uniquely identify a namespace in a Retis event
  collection. However the inode number is a value exposed to users, e.g. while
  looking at `/proc/<pid>/ns/net` or `/run/netns` (when using `iproute2` for the
  latter).

### Net device event section

```none
if {interface index} ({interface name}) rxif {rx interface index}
```

### VLAN hardware acceleration section

In the Linux kernel the VLAN data can be part of the metadata instead of inside
the packet (aka. "VLAN hardware acceleration"). This section displays this.

When not accelerated, the VLAN information is shown as part of the packet.

```none
vlan_accel (vlan {id} p {prio} [DEI])
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

## Packet info

### Ethernet section

```none
{src mac} > {dst mac} ethertype {etype name} ({etype hex})
```

### VLAN

```none
vlan {id} p {prio} [DEI] ethertype {etype name} ({etype hex})
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
{src ip}.{src port} > {dst ip}.{dst port} tos {tos} {ECN info} ttl {ttl} id {id}
    off {frag offset} [{flags}] len {packet len} opts [{IPv4 options}]
    proto {protocol name} ({protocol hex})
```

- `ECN info` can be one of `CE`, `ECT(0)` or `ECT(1)`.
- `flags` are constructed with a combination of `+`, `DF` and `rsvd`.

For IPv6:

```none
{src ip}.{src port} > {dst ip}.{dst port} {ECN info} ttl {ttl} label {flow label}
    len {packet len} exts [{IPv6 extensions}] proto {protocol name} ({protocol hex})
```

### TCP section

```none
flags [{flags}] seq {sequence} ack {acked sequence} win {window} [{options}]
```

- `flags` are constructed using a combination of `F` (fin), `S` (syn), `R`
  (reset), `P` (push), `.` (ack), `U` (urgent), `E` (ece), `W` (cwr) and `e`
  (RFC7560).
- `sequence` can be a range (`{start}:{end}`) or a single number (`{sequence}`).
- {options} are constructed by listing all options and for some extra
  information (mss, wscale, sack, echo, echoreply, cc, ccnew, ccecho, timestamp,
  tfo).

### UDP section

```none
len {UDP data len}
```

### ICMP & ICMPv6 sections

```none
type {type number} code {code number}
```

### Geneve

```none
geneve [{flags}] vni {vni} proto {etype name} ({etype hex}) opts_len {opts_len}
```

- `flags` are constructed using a combination of `O` (control) and `C`
  (critical).

### VXLAN

```none
vxlan [{flags}] vni {vni}
```

- `flags` can be `I` (set for a valid VNI).
