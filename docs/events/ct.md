# Conntrack event

## Metadata

State information,

```none
ct_state {state}
```

`state` is one of `ESTABLISHED`, `RELATED`, `NEW`, `REPLY`, `RELATED_REPLY` and
`UNTRACKED.`

Status information,

```none
status {status}
```

with `status` representing the bits set in `ct->status` in hex format.
See `enum ip_conntrack_status` in the kernel
[uapi headers](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nf_conntrack_common.h)
for the bitset representing the corresponding values.

## Connection information

This starts by a protocol specific part. For TCP, UDP and SCTP,

```none
{protocol name} ({proto state if any}) orig [{src ip}.{src port} > {dst ip}.{dst port} {proto specific}]
    reply [{src ip}.{src port} > {dst ip}.{dst port} {proto specific}] mark {mark} labels {labels}
```

where `{proto specific}` is optional protocol-specific information. For SCTP,
the verification tags are reported as `vtag {vtag}` in hex format.

For ICMP,

```none
icmp orig [{src ip} > {dst ip} type {type number} code {code number} id {id}]
    reply [{src ip} > {dst ip} type {type number} code {code number} id {id}]
```

Then the event has zone information, which can be one of `orig-zone {zone id}`,
`reply-zone {zone id}` and `zone {zone id}`.

Finally the event ends with `mark {mark} labels {labels}`. The `mark` is the
conntrack mark value that can be linked to an entry and the `labels` is an
hex-formatted bitfield value that represents the labels set for a given entry
(if none are set, the labels are not populated in the event).

## Parent connection information

If available, the parent connection information is printed on a new line and
shown as follow,

```none
\ parent [<parent connection information>]
```

The `<parent connection information>` has the same format as the connection
information above.
