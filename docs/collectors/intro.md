# Collectors

Collectors are optional data retrievers and event section producers used in the
collection mode (the `collect` sub-command). They are responsible of handling
specific data (eg. `skb`) or logical parts of the stack (eg. `ct`).

They can be enabled explicitly using the `--collectors` argument or
automatically started when that argument is not given. When started
automatically collectors check for prerequisites and can opt-out of the
collection (eg. the `ovs` collector won't run if OpenvSwitch is not used on the
target machine).

# Event sections

When an event is printed the exact form can vary depending on what data was
retrieved and collected. This depends on the data itself (which kind of packet
or metadata was retrieved) but also on the collection configuration (which
collectors are enabled, which options are set).

An event is always composed of a common section (containing a timestamp) and a
set of optional other sections. Those sections data can come from the eBPF
probes or from Retis directly. Sections are grouped in an event if they share a
common property (eg. they are all linked to a given packet + probe).

```none
<common> <kernel or userspace> <tracking> <drop> <stack trace> <...>
```

Each collector has a documentation page describing it and its event section.
