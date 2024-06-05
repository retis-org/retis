#ifndef __CORE_PROBE_COMMON_DEFS__
#define __CORE_PROBE_COMMON_DEFS__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/* Keep in sync with its Rust counterpart in crate::core::probe */
#define PROBE_MAX	1024

/* Global probe configuration, shared between kernel and user probes. Please
 * keep in sync with its Rust counterpart in crate::core::probe::common.
 */
struct retis_global_config {
	u8 enabled;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u8);
	__type(value, struct retis_global_config);
} global_config_map SEC(".maps");

static __always_inline bool collection_enabled() {
	struct retis_global_config *cfg;
	u8 key = 0;

	cfg = bpf_map_lookup_elem(&global_config_map, &key);
	return cfg && !!cfg->enabled;
}

#define COMMON_SECTION_CORE	0
#define COMMON_SECTION_TASK	1

/* Aligned with the log crate. */
enum {
	LOG_ERROR = 1,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG,
	LOG_TRACE,
};

/* Current log level. Actually set by user-space. */
const volatile u8 log_level = LOG_INFO;

/* Log macros must be used carefully and preferrably in the
 * {error,slow} path.
 * Useful exceptions must use a high log level (ideally LOG_TRACE).
 */
#define retis_log(lvl, fmt, args...)					\
({									\
	if (lvl <= log_level) {						\
		struct retis_log_event *__log =				\
			bpf_ringbuf_reserve(&log_map, sizeof(struct retis_log_event), 0); \
		if (__log) {						\
			__log->level = lvl;				\
			BPF_SNPRINTF(__log->msg, sizeof(__log->msg), fmt, args); \
			bpf_ringbuf_submit(__log, BPF_RB_FORCE_WAKEUP);	\
		}							\
	}								\
})

#define log_error(fmt, args...)	retis_log(LOG_ERROR, fmt, args)
#define log_warning(fmt, args...)	retis_log(LOG_WARN, fmt, args)
#define log_info(fmt, args...)		retis_log(LOG_INFO, fmt, args)
#define log_debug(fmt, args...)	retis_log(LOG_DEBUG, fmt, args)
#define log_trace(fmt, args...)	retis_log(LOG_TRACE, fmt, args)

struct retis_counters_key {
	/* Symbol address. */
	u64 sym_addr;
	/* pid of the process. Zero is used for the
	 * kernel as it is normally reserved the swapper task. */
	u64 pid;
};

/* Contains the counters of the error path.  This is then processed
 * and reported from user-space. */
struct retis_counters {
	u64 dropped_events;
};

/* Probe configuration; the key is the target symbol address */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROBE_MAX);
	__type(key, struct retis_counters_key);
	__type(value, struct retis_counters);
} counters_map SEC(".maps");

static __always_inline void err_report(u64 sym_addr, u32 pid)
{
	struct retis_counters *err_counters;
	struct retis_counters_key key;

	key.pid = pid;
	key.sym_addr = sym_addr;
	err_counters = bpf_map_lookup_elem(&counters_map, &key);
	/* Update only if exists. Any error here should be
	 * reported in a dedicated trace pipe. */
	if (err_counters)
		__sync_fetch_and_add(&err_counters->dropped_events, 1);
}

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define DIV_CEIL(m, n) (1 + ((m) - 1) / (n))

#endif /* __CORE_PROBE_COMMON_DEFS__ */
