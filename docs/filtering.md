# Filtering

Retis offers two distinct methods for filtering packets, both of which
can operate simultaneously:

- packet-based filtering which filters packets based on their content
  (headers).
- metadata-based filtering which filters packets based on their
  associated metadata.

These filtering mechanisms ensure that only relevant packets are
reported, so reducing the volume of uninteresting events and
improving the efficiency of packet tracing.

## Packet

Packet filtering uses a pcap-filter syntax. See `man pcap-filter` for an
overview on the syntax. Upon execution the pcap-filter gets compiled in cBPF
and subsequently translated into an eBPF program which in turn gets consumed by
the probes.

```none
$ retis collect -f 'tcp port 443'
...
```

Packet filtering can be of two types: L2 and L3. Retis automatically detects and
generates L2/L3 filters based on the expression. This allows to match both packets
fully formed and packets not having a valid L2 header yet (`sk_buff` having invalid
`mac_header` but valid and set `network_header`). One advantage of this approach is
the ability to match locally generated packets while still allowing matches based
on L2 criteria.

For example, the following filter:

```none
$ retis collect -f 'arp or tcp port 443'
L2+L3 packet filter(s) loaded
...
```

Internally generates two filters. For probes where only the `network_header`
is valid and set in the `sk_buff` the filter would match packets with tcp
source or destination port 443. For `sk_buff` with valid `mac_header` both arp
and tcp packets would be matched.
Please note that some limitations exist and they are a direct consequence of
libpcap capabilities.
For example filters like:

```none
$ retis collect -f 'ether broadcast or tcp port 443'
L2 packet filter(s) loaded
...
```

Will only generate L2 filters, that is, packets will be matched only if
`mac_header` is set.
For further information about the reason an L3 filter gets skipped, please
use the `--log-level debug` option, i.e.:

```none
$ retis --log-level debug collect -f 'ether broadcast or tcp port 443'
...
DEBUG Skipping L3 filter generation (Could not compile the filter: libpcap error: not a broadcast link).
INFO  L2 packet filter(s) loaded
...
```

## Metadata

Metadata filtering instead allows to write filters that match packets based
on their metadata.
These filters can match against any subfield of the `sk_buff` and subsequent
inner data structures.
Meta filtering also automatically follows struct pointers, so indirect access to
structures pointed by an `sk_buff` field is possible.
A filter expression is represented by this [pest](https://pest.rs/) grammar below:

```
--8<--
retis/src/core/filters/meta/meta.pest
--8<--
```

An example of a simple filter that respect a previous definition is:

```none
$ retis collect -m 'sk_buff.dev.nd_net.net.ns.inum == 4026531840'
...
```

The relational operators are:

1. `==` for *equal to*
2. `!=` for *not equal to*
3. `<` and `<=` for *less than* and *less than or equal to*
4. `>` and `>=` for *greater than* and *greater than or equal to*
5. if `op` and `rhs` are omitted in `term`, a *not equal to* zero numeric comparison is assumed

The boolean operators are:

1. `&&` with its alternate syntax `and` resulting true if both left and right conditions are `true`, `false` otherwise (conjunction)
2. `||` with its alternate syntax `or` resulting true if at least one between left and right conditions are `true`, `false` otherwise (disjunction)


Boolean operators have the same precedence, meaning in absence of
explicit syntax, they are considered left-associative.
In order to define different associativity in the expression, parentheses are available.
Parentheses **MUST** be well-formed and can **arbitrarily** change the assiociativity of the
operators and so the way the expression is evaluated.

For example, the following expression:

```none
$ retis collect -m 'sk_buff.pkt_type == 0x0 || sk_buff.mark == 0x100 && sk_buff.cloned'
```

logically results in:

```none
0: if sk_buff.pkt_type == 0 goto 4
1: goto 2
2: if sk_buff.mark == 256 goto 4
3: goto 7
4: if sk_buff.cloned != 0 goto 6
5: goto 7
6: true
7: false
```

which is semantically equivalent to:

```none
$ retis collect -m '(sk_buff.pkt_type == 0x0 || sk_buff.mark == 0x100) && sk_buff.cloned'
```

conversely, the following:

```none
$ retis collect -m 'sk_buff.pkt_type == 0x0 || (sk_buff.mark == 0x100 && sk_buff.cloned)'
```

results in:

```none
0: if sk_buff.pkt_type == 0 goto 6
1: goto 2
2: if sk_buff.mark == 256 goto 4
3: goto 7
4: if sk_buff.cloned != 0 goto 6
5: goto 7
6: true
7: false

```

There's **no limit** to the use of paretheses and boolean operators, but a
short-circuit evaluation strategy is applied, so it's highly suggested
to define the expression accordingly in order to avoid unnecessary
runtime overhead.

At the moment, only numeric and string comparisons are supported.
The right-hand side (`rhs`) of numeric matches must be expressed as
literal and can be represented in either base 10, base 16 if
starting with `0x` prefix, or base 2 if starting with `0b` prefix.

An example of equivalent numeric expressions with different bases are:

```none
sk_buff.mark == 16
sk_buff.mark == 0x10
sk_buff.mark == 0b10000
```

All the relational operators support numbers (both unsigned in any base
and signed in base 10). The usage of negative numbers is only allowed against
signed members.
Bitfields are supported as well (both signed and unsigned) and they
are treated as regular numbers.
For numeric comparisons, an additional bitwise AND operation can be
performed by specifying a *mask*.
A `mask` can be expressed as a hexadecimal number (e.g. *0xdeaf*), a
binary number (e.g. *0b01010101*), and a regular decimal number and
**MUST** strictly be positive.
The filtering engine allows you to specify masks up to **u64::MAX**
with any target. While this approach is safe, ensuring consistency is
the user's responsibility.
The following example demonstrates this approach:

```
$ retis collect -m 'sk_buff._nfct:0x7 == 0x2'
...
```

which is equivalent to the following:

```none
(sk_buff->_nfct & NFCT_INFOMASK) == IP_CT_NEW
```

For strings only the operators *equal to* and *not equal to* are supported,
furthermore, the string (`rhs`) must be enclosed between *quotes*.

```none
$ retis collect -m 'sk_buff.dev.name == "eth0"'
...
```

The example above shows how strings can be matched and how they are
required to be quoted.

Another useful feature meta filtering expose is the ability to follow
pointers embedded in members with a different defined type.
For example, the filter below:

```none
$ retis collect -m sk_buff._nfct:~0x7:nf_conn.mark
...
```

is equivalent to the following:

```none
((struct nf_conn *)(skb->_nfct & NFCT_PTRMASK))->mark != 0
```

Please, notice in the previous example the operator `~` which is
semantically equivalent to a `bitwise not`.
`Bitwise not` is only applicable to masks (in any base).

Metadata filtering, being a BTF-based way of filtering, is theoretically
not limited to `sk_buff`, so from a generic point of view it can support
all filters under the form *struct_type_name.field1.field2.field3* with
the above constraints, but for the time being only `struct sk_buff` is
supported.
This implies that the `sk_buff` keyword **MUST** always be present and **MUST**
always appear first in each expression.

It is possible to combine packet and meta filtering, and doing so is just a
matter of specifying their respective options and filters.

```none
$ retis collect -f 'tcp port 443' -m 'sk_buff.dev.name == "eth0"'
...
```

The above options will be concatenated, meaning that both filters must match
in order to have a match and generate events for packets.
