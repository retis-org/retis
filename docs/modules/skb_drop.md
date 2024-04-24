# SKB drop collector

The `skb-drop` collector provides information about why an skb was dropped. This
collector acts on the `enum skb_drop_reason` values, although it also
understands non-core drop reasons such as `enum ovs_drop_reason`. The `skb-drop`
collector also adds a probe on the `skb:kfree_skb` tracepoint.

## Event

```none
drop (reason {drop reason})
```
