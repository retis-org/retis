#ifndef __CORE_FILTERS_PACKETS_PACKET_FILTER__
#define __CORE_FILTERS_PACKETS_PACKET_FILTER__

#include <common_defs.h>

struct retis_packet_filter_ctx {
	/* Input */
	char *data;		/* points to the beginning of the mac header. */
	unsigned int len;	/* linear length. */
	/* Output */
	unsigned int ret;	/* outcome of the match (zero if miss). */
} __binding;

/* We need an actual define here because __FILTER_MAX_INSNS is used by the
 * pre-processor who doesn't know about enums yet.
 */
#define __FILTER_MAX_INSNS	4096
BINDING_DEF(FILTER_MAX_INSNS, __FILTER_MAX_INSNS)

#define __s(v) #v
#define s(v) __s(v)

BINDING_DEF(STACK_RESERVED, 8)
BINDING_DEF(SCRATCH_MEM_SIZE, 4)

/* 8 bytes for probe_read_kernel() outcome plus 16 * 4 scratch
 * memory locations for cbpf filters. Aligned to u64 boundary.
 */
BINDING_DEF(SCRATCH_MEM_START, 16 * SCRATCH_MEM_SIZE + STACK_RESERVED)

#define l2 0xdeadbeef
#define l3 0xdeadc0de
enum filter_type {
	L2 = l2,
	L3 = l3,
} __binding;

#endif
