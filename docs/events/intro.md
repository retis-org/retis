# Event sections

When an event is printed the exact form can vary depending on what data was
retrieved and collected. This depends on the data itself (which kind of packet
or metadata was retrieved) but also on the collection configuration (which
collectors were enabled, which options were set, see the [collectors
documentation](../collectors/overview.md) for more details).

An event is always composed of a common section (containing a timestamp) and a
set of optional other sections. Those sections data can come from the eBPF
probes or from Retis directly. Sections are grouped in an event if they share a
common property (eg. they are all linked to a given packet + probe).

```none
<common> <kernel or userspace> <tracking> <drop> <stack trace> <...>
```

Each event section has its own dedicated documentation page.
