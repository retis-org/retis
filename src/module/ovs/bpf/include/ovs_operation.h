#ifndef __MODULE_OVS_OPERATION__
#define __MODULE_OVS_OPERATION__

#include "ovs_common.h"

/* Please keep in sync with its Rust counterpart in retis-events::ovs. */
enum ovs_operation_type {
	OVS_OP_EXEC = 0,
	OVS_OP_PUT = 1,
};

/* Please keep in sync with its Rust counterpart in retis-events::ovs. */
struct ovs_operation_event {
	/* enum ovs_operation_type */
	u8 type;
	u32 queue_id;
	u64 batch_ts;
	u8 batch_idx;
};

/* Upcall Batching.
 *
 * ovs-vwitchd processes upcalls in batches. This means that it first receives
 * up to 64 upcall events and processes them all in one go before receiving the
 * next batch.
 *
 * A batch can be either "batching" or "processing". When the first upcall is
 * received we start batching. Each subsequent OVS_RECV_UPCALL event is counted.
 *
 * When the first operation (flow_put or flow_exec) is detected on the batch,
 * the batch is set to "processing" mode. Each operation processed on each
 * upcall in the batch is tracked until no more elements are left.
 *
 * We track the state of this batching for each handler of ovs-vswitchd's
 * handler threads.
 */

/* Upcall information that is carried through userspace events
 * Please keep in sync with its Rust counterpart in crate::module::ovs::ovs.rs.
 */
struct user_upcall_info {
	u32 queue_id;

	/* Bitmask of processed operations. Bit order corresponds to
	 * enum ovs_operation_type values.*/
	u8 processed_ops;

	/* It indicates that the upcall event was filtered out so no events
	 * related to this upcall should be generated. */
	bool skip_event;
};

#define UPCALL_MAX_BATCH 64

/* Upcall batch information.
 * Please keep in sync with its Rust counterpart in crate::module::ovs::ovs.rs.
 */
struct upcall_batch {
	u64 leader_ts;	 /* Timestamp of the first upcall in the batch. */
	bool processing;		/* Whether we're still batching (false) or we
				are processing batched upcalls. */
	u8 current_upcall; /* Current upcall being processed */
	u8 total;		  /* Number of upcalls of the batch */
	struct user_upcall_info upcalls[UPCALL_MAX_BATCH]; /* Upcalls in batch */
};


/* Array of batches. This is a placeholder as this array must be created
 * in userspace setting the correct size to the number of handlers. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct upcall_batch);
} upcall_batches SEC(".maps");

/* Hash table that maps handler pids with indexes in the upcall_batches array.
 * This double lookup allows us to pre-allocate the batch objects not requiring
 * the use of stack space.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
} pid_to_batch SEC(".maps");

/* Get the batch for the current handler thread. */
static __always_inline struct upcall_batch *batch_get() {
	u32 *idx;
	u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

	idx = bpf_map_lookup_elem(&pid_to_batch, &pid);
	if (!idx)
		return NULL;

	return bpf_map_lookup_elem(&upcall_batches, idx);
}

/* Initialize a batch. */
static __always_inline void batch_init(struct upcall_batch *batch) {
	if (!batch)
		return;

	batch->processing = false;
	batch->leader_ts = 0;
	batch->current_upcall = 0;
	batch->total = 0;
}

/* Set the batch in processing mode. */
static __always_inline void batch_start_processing(struct upcall_batch *batch) {
	if (!batch)
		return;
	batch->current_upcall = 0;
	batch->processing = true;
}

static __always_inline bool batch_is_processing(const struct upcall_batch *batch) {
	if (!batch)
		return false;
	return batch->processing;
}

/* Retrieve the current upcall being processed. */
static __always_inline struct user_upcall_info *batch_current(struct upcall_batch *batch) {
	/* In some cases the branch get optimized. The barrier below
	 * appear to prevent that making the verifier happy.
	 */
	barrier_var(batch->current_upcall);
	if (!batch ||
	    batch->current_upcall >= (UPCALL_MAX_BATCH -1))
		return NULL;

	return &batch->upcalls[batch->current_upcall];
}

/* Retrieve the next upcall. */
static __always_inline struct user_upcall_info *batch_next(struct upcall_batch *batch) {
	if (!batch ||
		batch->current_upcall >= (batch->total -1) ||
		batch->current_upcall >= (UPCALL_MAX_BATCH -1) )
		return NULL;

	batch->current_upcall += 1;

	return batch_current(batch);
}

/* Put and return a new upcall in the batch. */
static __always_inline struct user_upcall_info *batch_put(struct upcall_batch *batch) {
	struct user_upcall_info *dst;

	if (!batch) {
		return NULL;
	}
	if (batch->total >= UPCALL_MAX_BATCH -1) {
		return NULL;
	}

	dst = &batch->upcalls[batch->total];
	__builtin_memset(dst, 0, sizeof(*dst));
	batch->total += 1;

	return dst;
}

/* Process an upcall receive event. */
static __always_inline struct upcall_batch *batch_process_recv(u64 timestamp,
							       u32 queue_id,
							       bool skip)
{
	struct upcall_batch *batch = batch_get();
	struct user_upcall_info *info;

	if (!batch)
		return NULL;

	if (batch_is_processing(batch)) {
		batch_init(batch);
	}

	info = batch_put(batch);
	if (!info)
		return NULL;

	info->queue_id = queue_id;
	info->skip_event = skip;

	if (batch->total == 1) {
		/* First of the batch. */
		batch->leader_ts = timestamp;
	}

	return batch;
}

/* Process an operation event and populate the event with the batch
 * information.
 * If an event is generated, it's returned in *op. */
static __always_inline int batch_process_op(enum ovs_operation_type type,
					    struct retis_raw_event *event,
					    struct ovs_operation_event **op)
{
	struct upcall_batch *batch;
	struct user_upcall_info *info;
	u8 op_flag = 0x1 << type;

	if (op)
		*op = NULL;

	batch = batch_get();
	if (!batch)
		return -1;

	if (!batch->total)
		/* There are no elements in this batch. This probably means
		 * we missed the recv_upcall event (e.g: we started collecting
		 * events after it happened). */
		return 0;

	if (!batch_is_processing(batch)) {
		batch_start_processing(batch);
	}

	info = batch_current(batch);
	if (!info)
		return -1;

	if (info->processed_ops & op_flag) {
		/* An operation cannot be done twice on the same upcall.
		 * This event must correspond to the next upcall in the batch. */
		info = batch_next(batch);
		if (!info)
			return -1;
	}
	info->processed_ops |= op_flag;

	if (info->skip_event)
		return 0;

	struct ovs_operation_event *op_event =
		get_event_zsection(event, COLLECTOR_OVS, OVS_OPERATION,
				   sizeof(*op_event));
	if (!op_event)
		return 0;

	op_event->type = type;
	op_event->queue_id = info->queue_id;
	op_event->batch_ts = batch->leader_ts;
	op_event->batch_idx = batch->current_upcall;

	if (op)
		*op = op_event;

	return 0;
}

#endif /* __MODULE_OVS_OPERATION__ */
