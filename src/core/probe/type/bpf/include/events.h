#ifndef __CORE_PROBE_TYPE_BPF_EVENTS__
#define __CORE_PROBE_TYPE_BPF_EVENTS__

/* Keep this file in sync with its Rust counterpart in src/core/probe/events.rs
 */

#define EVENTS_MAX	512

struct event {
	u64 ksym;
	u64 timestamp;

	u16 skb_etype;
	u8 rsvd[14];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct event) * EVENTS_MAX);
} event_map SEC(".maps");

#endif /* __CORE_PROBE_TYPE_BPF_EVENTS__ */
