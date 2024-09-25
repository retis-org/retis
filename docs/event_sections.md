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

The `collector` sections are described in the collector specific pages.

## Common section

```none
{timestamp} ({smp id}) [{comm}] {pid}/{tgid}
```

- `timestamp` can be formatted in different ways based on the configuration.

## Kernel section

```none
[{probe type}] {symbol name}
```

- `probe type` can be "tp" (raw tracepoint), "k" (kprobe) or "kr" (kretprobe).

## Userspace section

```none
[u] {symbol name}
```

## Tracking section

```none
#{tracking id} (skb {skb address}) n {event index}
```

- `tracking id` identifies a packet with a unique number across a given
  collection of events. It can be used to reconstruct packet flows. Note that
  this id can be shared between skbs, eg. for clones.
- `skb address`: the address of the `skb`, which can be used to distinguished
  between `skb` sharing the same `tracking id`.
- `event index`: when an event is part of a series of events (this is only
  available at post-processing time when using the `sort` sub-command), this
  indicates the index of the event in the series.

## Startup section

```none
Retis version {version}
```

Contains the `version` of the Retis binary that collected the event series as
well as timing information for being able to display time in UTC at
post-processing time. Only the `version` is shown in the output.

This section is emitted when a collection is started.
