# Packet event

The `packet` event section holds raw networking packets and is used to display
their fields.

## Ethernet

```none
{src mac} > {dst mac} ethertype {etype name} ({etype hex})
```

## VLAN

```none
vlan {id} p {prio} [DEI] ethertype {etype name} ({etype hex})
```

## ARP

```none
request who-has {ip} tell {ip}
```

or,

```none
reply {ip} is at {mac}
```

## IP

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

## TCP

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

## UDP

```none
len {UDP data len}
```

## ICMP & ICMPv6

```none
type {type number} code {code number}
```

## Geneve

```none
geneve [{flags}] vni {vni} proto {etype name} ({etype hex}) opts_len {opts_len}
```

- `flags` are constructed using a combination of `O` (control) and `C`
  (critical).

## VXLAN

```none
vxlan [{flags}] vni {vni}
```

- `flags` can be `I` (set for a valid VNI).
