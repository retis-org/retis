# Skb event

Full `skb` collector events will be constructed with the following. Non-reported
or invalid fields are automatically hidden.

## VLAN hardware acceleration

In the Linux kernel the VLAN data can be part of the metadata instead of inside
the packet (aka. "VLAN hardware acceleration"). This section displays this.

When not accelerated, the VLAN information is shown as part of the packet.

```none
vlan_accel (ethertype {etype name} ({etype hex}) vlan {id} p {prio} [DEI])
```

## Metadata & dataref

Those two sections report metadata and reference counting from the socket buffer
itself.

```none
skb [{csum} hash {skb hash} data_len {skb data lenght} priority {skb priority}
    {flags} fclone {fast clone count} users {user count} dataref {skb refcount}]
```

- `csum` information, the format is slightly different depending on the checksum
  status (`none`, `unnecessary`, `partial` or `complete`).
- `flags` are a combination of `nohdr` and `cloned`.

## Generic segmentation offload (GSO)

Generic Segmentation Offload information linked to an `skb` (see
`skb_shared_info`).

```none
gso [type {GSO type} flags {GSO flags} frags {nr of GSO frags}
    segs {nr of GSO segs} size {GSO size}]
```

- `GSO type`, see `SKBFL_*` in the Linux kernel `include/linux/skbuff.h`.
- `GSO flags`, see `SKB_GSO_*` in the Linux kernel `include/linux/skbuff.h`.
