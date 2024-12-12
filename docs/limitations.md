# Limitations

Known and current limitations:

- By default Retis does not modify the system (e.g. load kernel modules, change
  the configuration, add a firewalling rule). This is done on purpose but might
  mean some prerequisites will be missing if not added manually. The only
  example for now is the `nft` module that requires a specific nft rule to be
  inserted. If that rule is not there, no nft event will be reported. To allow
  Retis to modify the system, use the `--allow-system-changes` option when
  running the `collect` command. See `retis collect --help` for further details
  about changes applied to the system.

- Retis operates mainly on `struct sk_buff` objects meaning a good part of
  locally generated traffic can't be traced at the moment. E.g. locally
  generated traffic from a container can be traced when it exits the container.

- Profiles combination might fail if flags are used multiple times or if some
  arguments are incompatible. Use with care.

Additional notes (not strictly limitations):

- Filtering & tracking packets being modified can only work if the packet is at
  least seen once in a form where it can be matched against the filter. E.g.
  tracking SNATed packets only in `skb:consume_skb` with a filter on the
  original address won't generate any event.

- As explained in the [filtering section](https://retis.readthedocs.io/en/stable/#filtering)
  filters are eventually translated to eBPF instructions. Currently, the maximum
  size of an eBPF filter is 4096 instructions.

- Some fields present in the packet might not be reported when probes are early
  in the stack, while being shown in later ones. This is because Retis probes
  rely on the networking stack knowledge of the packet and if some parts weren't
  processed yet they can't be reported. E.g. TCP ports won't be reported from
  `kprobe:ip_rcv`.