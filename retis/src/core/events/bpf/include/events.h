#ifndef __CORE_PROBE_KERNEL_BPF_EVENTS__
#define __CORE_PROBE_KERNEL_BPF_EVENTS__

#include <vmlinux.h>

#include <common_defs.h>

/* Please keep the below in sync with its Rust counterpart. */
#define EVENTS_MAX		8 * 1024
#define RAW_EVENT_DATA_SIZE	1024 - 2 /* Remove the size field */
#define RETIS_MAX_COMM		64

/* Please keep the below in sync with its Rust counterpart. */
#define LOG_MAX			127

BINDING_DEF(LOG_EVENTS_MAX, 128)

struct retis_log_event {
	u8 level;
	char msg[LOG_MAX];
} __binding;

/* We're using the factory identifiers defined in retis-events.
 * Please keep in sync. */
enum retis_event_owners {
	COMMON = 1,
	KERNEL = 2,
	USERSPACE = 3,
	COLLECTOR_SKB_TRACKING = 4,
	COLLECTOR_SKB_DROP = 5,
	COLLECTOR_SKB = 6,
	COLLECTOR_OVS = 7,
	COLLECTOR_NFT = 8,
	COLLECTOR_CT = 9,
	COLLECTOR_DEV = 10,
	COLLECTOR_NS = 11,
};

struct retis_raw_event {
	u16 size;
	u8 data[RAW_EVENT_DATA_SIZE];
} __packed;

/* Please keep synced with its Rust counterpart. */
struct retis_raw_event_section_header {
	u8 owner;
	u8 data_type;
	u16 size;
} __packed;

/* Please keep synced with its Rust counterpart. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct retis_raw_event) * EVENTS_MAX);
} events_map SEC(".maps");

/* Please keep synced with its Rust counterpart. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct retis_log_event) * LOG_EVENTS_MAX);
} log_map SEC(".maps");

static __always_inline struct retis_raw_event *get_event()
{
	struct retis_raw_event *event;

	event = bpf_ringbuf_reserve(&events_map, sizeof(*event), 0);
	if (!event)
		return NULL;

	event->size = 0;
	return event;
}

static __always_inline void discard_event(struct retis_raw_event *event)
{
	bpf_ringbuf_discard(event, 0);
}

static __always_inline void send_event(struct retis_raw_event *event)
{
	bpf_ringbuf_submit(event, 0);
}

static __always_inline void *get_event_section(struct retis_raw_event *event,
					       u8 owner, u8 data_type, u16 size)
{
	struct retis_raw_event_section_header *header;
	u16 requested, left;
	void *section;

	/* Keep the verifier happy, as we're going to substract one to the other
	 * below. This can't happen in practice.
	 */
	if (unlikely(event->size > sizeof(event->data)))
	    return NULL;

	requested = sizeof(*header) + size;
	left = sizeof(event->data) - event->size;

	if (unlikely(requested > left)) {
		log_error("Failed to get event section: no space left (%u > %u)",
			  requested, left);
		return NULL;
	}

	header = (struct retis_raw_event_section_header *)
			(event->data + event->size);
	header->owner = owner;
	header->data_type = data_type;
	header->size = size;

	section = (void *)header + sizeof(*header);
	event->size += requested;

	return section;
}

/* Similar to get_event_section but initialize the section data to 0s. */
static __always_inline void *get_event_zsection(struct retis_raw_event *event,
						u8 owner, u8 data_type, const u16 size)
{
	void *section = get_event_section(event, owner, data_type, size);

	if (!section)
		return NULL;

	__builtin_memset(section, 0, size);
	return section;
}

static __always_inline u16 get_event_size(struct retis_raw_event *event)
{
	return event->size;
}

struct common_event {
	u64 timestamp;
	u32 smp_id;
} __binding;

struct common_task_event {
	u64 pid;
	char comm[RETIS_MAX_COMM];
} __binding;

#endif /* __CORE_PROBE_KERNEL_BPF_EVENTS__ */
