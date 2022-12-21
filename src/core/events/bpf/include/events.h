#ifndef __CORE_PROBE_KERNEL_BPF_EVENTS__
#define __CORE_PROBE_KERNEL_BPF_EVENTS__

#include <vmlinux.h>

/* Please keep both synced with its Rust counterpart. */
#define EVENTS_MAX		512
#define RAW_EVENT_DATA_SIZE	1024 - 2 /* Remove the size field */

/* Please keep in sync with its Rust counterpart in crate::core::events::raw. */
enum trace_event_owners {
	COMMON = 1,
	KERNEL = 2,
	USERSPACE = 3,
	COLLECTOR_SKB_TRACKING = 4,
};

struct trace_raw_event {
	u16 size;
	u8 data[RAW_EVENT_DATA_SIZE];
} __attribute__((packed));

/* Please keep synced with its Rust counterpart. */
struct trace_raw_event_section_header {
	u8 owner;
	u8 data_type;
	u16 size;
} __attribute__((packed));

/* Please keep synced with its Rust counterpart. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct trace_raw_event) * EVENTS_MAX);
} events_map SEC(".maps");

static __always_inline struct trace_raw_event *get_event()
{
	struct trace_raw_event *event;

	event = bpf_ringbuf_reserve(&events_map, sizeof(*event), 0);
	if (!event)
		return NULL;

	event->size = 0;
	return event;
}

static __always_inline void discard_event(struct trace_raw_event *event)
{
	bpf_ringbuf_discard(event, BPF_RB_NO_WAKEUP);
}

static __always_inline void send_event(struct trace_raw_event *event)
{
	bpf_ringbuf_submit(event, 0);
}

static __always_inline void *get_event_section(struct trace_raw_event *event,
					       u8 owner, u8 data_type, u16 size)
{
	struct trace_raw_event_section_header *header;
	u16 left = RAW_EVENT_DATA_SIZE - event->size;
	void *section;

	if (sizeof(*header) + size > left || event->size > sizeof(event->data))
		return NULL;

	header = event->data + event->size;
	header->owner = owner;
	header->data_type = data_type;
	header->size = size;

	section = event->data + event->size + sizeof(*header);
	event->size += sizeof(*header) + size;

	return section;
}

struct common_event {
	u64 timestamp;
} __attribute__((packed));

#endif /* __CORE_PROBE_KERNEL_BPF_EVENTS__ */
