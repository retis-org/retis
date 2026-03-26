# Packet event

The `packet` event section holds raw networking packets and is used to display
their fields.

Retis parses headers layer by layer, displaying information for each supported
protocol as described in the sections below. Depending on how far parsing
progresses, the output falls into one of three cases:

- **All headers parsed**: the output is fully printed with no trailing
  indicator.

- **Unsupported protocol encountered**: parsing stops at the unsupported layer
  and the output ends with `... ({protocol} not supported, use 'retis pcap')`.
  There may be interesting data further down the payload that is not shown.

- **Truncated or incomplete data**: headers are expected but not enough data was
  available (e.g. due to snap length truncation); parsing stops early and the
  output ends with `... (truncated or incomplete packet)`.

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
geneve [{flags}] vni {vni} proto {etype name} ({etype hex}) [{options}]
```

- `flags` are constructed using a combination of `O` (control) and `C`
  (critical).
- `options` is a list of options separated by commas of the following form:
  `class {class} type {type} len {len}`. `type` includes a trailing "(C)" if the
  option type has the critical bit set.

If the Netdev GRO hint option is used the above `options` will contain
additional information of the following form:

```none
(proto {inner proto id} {nested IP version} nh {nested nh offset}
    tp {nested tp offset} hlen {nested header len})
```

## VXLAN

```none
vxlan [{flags}] vni {vni}
```

- `flags` can be `I` (set for a valid VNI).

## MACsec

```none
an {association number} pn {packet number} [{flags}] sl {short length} sci {sci}
```

- `flags` are constructed following the bits set in the `tci` field with a
  combination of `E` (encrypted payload), `C` (changed text), `S` (end station),
  `B` (single copy broadcast) and `I` (SCI present).

## IPsec

### ESP

In case a packet has an ESP header, processing of the packet will stop there as
the rest is encrypted.

```none
spi {spi} seq {sequence number}
```

### AH

```none
spi {spi} seq {sequence number} icv {icv}
```

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

- `init_tag` is printed as hex.

**INIT ACK**

```none
[INIT ACK init_tag {init_tag} rwnd {rwnd} OS {os} MIS {mis} init_TSN {tsn}]
```

- `init_tag` is printed as hex.

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
