# Conntrack collector

The `ct` collector reports information collected from socket buffers
(`struct sk_buff`) about their conntrack status. This is done by reading the
`_nfct` field of an `skb`.

The reported information in the events contains conntrack status and protocol
specific data. Currently supported protocols are IPv4/6, TCP, UDP and ICMP.

## Events

The `ct` events will be constructed with the following.

### Metadata

State information,

```none
ct_state {state}
```

`state` is one of `ESTABLISHED`, `RELATED`, `NEW`, `REPLY`, `RELATED_REPLY` and
`UNTRACKED.`

### Connection information

This starts by a protocol specific part. For TCP and UDP,

```none
{protocol name} ({TCP state if any}) orig [{src ip}.{src port} > {dst ip}.{dst port}]
    reply [{src ip}.{src port} > {dst ip}.{dst port}]
```

For ICMP,

```none
icmp orig [{src ip} > {dst ip} type {type number} code {code number} id {id}]
    reply [{src ip} > {dst ip} type {type number} code {code number} id {id}]
```

Then the event ends up with zone information, which can be one of `orig-zone
{zone id}`, `reply-zone {zone id}` and `zone {zone id}`.

### Parent connection information

If available, the parent connection information is then shown as follow,

```none
parent [<parent connection information>]
```

The `<parent connection information>` has the same format as the connection
information above.
