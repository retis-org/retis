# Core events

Some data is collected or generated directly by the core logic in Retis and not
by optional collectors. Those sections are quite generic and can't be enabled
nor disabled.

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
Machine info {kernel_release} {kernel_version} {machine}
```

Contains the `version` of the Retis binary that collected the event series, some
machine-related information as in `uname -rvm` from the machine the data was
collected, and timing information for being able to display time in UTC at
post-processing time. The timing information is not displayed in the output.

This section is emitted when a collection is started.
