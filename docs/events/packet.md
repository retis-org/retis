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

## SCTP

```none
vtag {vtag} [{chunk}] [{chunk}] ...
```

- `vtag` is the verification tag, printed as hex value.
- Each chunk is enclosed in `[...]` and preceded by a space. Multiple chunks in the
  same packet are printed sequentially separated by a space.
- Some fields in chunks may be skipped depending on packet truncation and Retis
  snap length.

### Chunk types

**DATA**

```none
[DATA ({flags}) TSN {tsn} SID {sid} SSEQ {sseq} PPID {ppid}]
```

- `flags` are constructed using a combination of `U` (unordered), `B` (beginning
  fragment) and `E` (ending fragment). The `({flags})` part is omitted when none
  of these flags are set.
- `ppid` is printed as hex.

**INIT**

```none
[INIT init_tag {init_tag} rwnd {rwnd} OS {os} MIS {mis} init_TSN {tsn}]
```

**INIT ACK**

```none
[INIT ACK init_tag {init_tag} rwnd {rwnd} OS {os} MIS {mis} init_TSN {tsn}]
```

**SACK**

```none
[SACK cum_ack {cum_tsn} a_rwnd {a_rwnd} #gap_acks {n_gap} #dup_tsns {n_dup}]
```

**Other known chunks**

`[HEARTBEAT]`, `[HEARTBEAT_ACK]`, `[ABORT]`, `[SHUTDOWN]`, `[SHUTDOWN_ACK]`,
`[ERROR]`, `[COOKIE_ECHO]`, `[COOKIE_ACK]`, `[ECNE]`, `[CWR]`,
`[SHUTDOWN_COMPLETE]`.

- No additional fields are included in the above.

**Unknown chunk type**

```none
[UNKNOWN:{type}]
```

- Normally, in well formed packets this is never present as this is just a
  fallback for unknown chunks.
- `type` is the raw decimal chunk type value.
