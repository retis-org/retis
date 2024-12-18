# Nft collector

The `nft` collector provides insight into Netfilter rules and actions, by
automatically adding a probe on `__nft_trace_packet`. For the `nft` collector to
work a special dummy `nft` table must be added:

```none
table inet Retis_Table {
    chain Retis_Chain {
        meta nftrace set 1
    }
}
```

Retis can also install and uninstall the above table automatically by using the
`--allow-system-changes` cli parameter.

## Arguments

The `nft` collector has a single specific argument, `--nft-verdicts`. It is used
to choose which Netfilter verdicts will be reported in events. By default it
reports only `drop` and `accept` verdicts.

## Event

```none
table {table name} ({table handle}) chain {chain name} ({chain handle})
    handle {rule handle} {verdict} chain {chain name}
```

With `verdict` being the verdict name and an optional `(policy)` flag if it is
not explicit and comes from the policy.

## Linking an event to a given rule in the Netfilter configuration

The `nft` collector will output events like the following:

```none
$ retis collect --allow-system-changes -c nft
53529978697438 [swapper/0] 0 [k] __nft_trace_packet
  table firewalld (2) chain filter_PREROUTING (164) accept (policy)

53529978701985 [swapper/0] 0 [k] __nft_trace_packet
  table firewalld (2) chain filter_INPUT (165) handle 169 accept
```

We can see in the above that the table "firewalld" (handle 2) was traversed and
accept rules were hit:

- Chain "filter_PREROUTING" (handle 164) default policy (accept) was hit.
- Chain "filter_PREROUTING" (handle 165) had one of its rules hit (handle 169)
  which is an accept action.

The Netfilter rule set can be dumped including handles, by using the following
command:

```none
$ nft -a list ruleset
[...]
table inet firewalld { # handle 2
    [...]
	chain filter_PREROUTING { # handle 164
		type filter hook prerouting priority filter + 10; policy accept;
		icmpv6 type { nd-router-advert, nd-neighbor-solicit } accept # handle 197
		meta nfproto ipv6 fib saddr . mark . iif oif missing drop # handle 195
	}

	chain filter_INPUT { # handle 165
		type filter hook input priority filter + 10; policy accept;
		ct state { established, related } accept # handle 169
		ct status dnat accept # handle 170
		iifname "lo" accept # handle 171
		ct state invalid drop # handle 172
		jump filter_INPUT_ZONES # handle 176
		reject with icmpx admin-prohibited # handle 177
	}
    [...]
}
[...]
```

Using this events can be mapped to the `nft` configuration. First packet hit
the accept policy below:

```none
chain filter_PREROUTING { # handle 164
	type filter hook prerouting priority filter + 10; policy accept;    <--

```

Second packet hit the accept action below:

```none
chain filter_INPUT { # handle 165
	type filter hook input priority filter + 10; policy accept;
	ct state { established, related } accept # handle 169               <--
```

Note: by using the `skb` collector in addition to the `nft` one, the specific
packet that triggered those events can be reported.
