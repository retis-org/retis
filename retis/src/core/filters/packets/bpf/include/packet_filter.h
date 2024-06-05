#ifndef __CORE_FILTERS_PACKETS_PACKET_FILTER__
#define __CORE_FILTERS_PACKETS_PACKET_FILTER__

#include <bpf/bpf_helpers.h>

/* Defines the context passed to the packet filtering
 * facility. Includes both input and output.
 * Keep in sync with its Rust counterpart in
 * core::filters::packets::ebpf.
 */
struct retis_packet_filter_ctx {
	/* Input */
	char *data;		/* points to the beginning of the mac header. */
	unsigned int len;	/* linear length. */
	/* Output */
	unsigned int ret;	/* outcome of the match (zero if miss). */
} __attribute__((packed));

#define FILTER_MAX_INSNS 4096

#define __s(v) #v
#define s(v) __s(v)

/* Reserve FILTER_MAX_INSNS - (instruction placeholder) */
#define RESERVE_NOP				\
	".rept " s(FILTER_MAX_INSNS) " - 1;"	\
	"goto +0x0;"				\
	".endr;"

/* Keep in sync with its Rust counterpart in
 * crate::core::filters::packets::ebpf
 */
#define STACK_RESERVED		8
#define SCRATCH_MEM_SIZE	4
/* 8 bytes for probe_read_kernel() outcome plus 16 * 4 scratch
 * memory locations for cbpf filters. Aligned to u64 boundary.
 */
#define SCRATCH_MEM_START	16 * SCRATCH_MEM_SIZE + STACK_RESERVED

#define STACK_SIZE		SCRATCH_MEM_START

enum {
	FILTER_L2 = 0xdeadbeef,
	FILTER_L3 = 0xdeadc0de,
};

/* The function below defines a placeholder instruction and a
 * nop frame that will be replaced on load with the actual filtering
 * instructions.
 * Normally, if no filter gets set, a simple mov r0, 0x40000 will replace
 * the call. 0x40000 is used as it is also used by generated cBPF filters,
 * whereas 0 means no match, instead. The exceeding nops will get removed
 * from the kernel during the load. If no explicit, nor default filter gets
 * set, call 0xdeadbeef for the l2 variant or 0xdeadc0de for the l3 will
 * fail to load and the verifier will report an error.
 */
static __always_inline
unsigned int packet_filter(struct retis_packet_filter_ctx *ctx, u32 placeholder)
{
	register struct retis_packet_filter_ctx *ctx_reg asm("r1");
	u8 stack[STACK_SIZE] __attribute__ ((aligned (8)));
	register u64 *fp asm("r9");

	if (!ctx)
		return 0;

	ctx_reg = ctx;
	fp = (u64 *)((void *)stack + sizeof(stack));

	asm volatile (
		"call %[filter];"
		RESERVE_NOP
		"*(u32 *)%[ret] = r0;"
		: [ret] "=m" (ctx->ret)
		: [filter] "i" (placeholder),
		  "r" (ctx_reg),
		  "r" (fp)
		: "r0", "r1", "r2", "r3",
		  "r4", "r5", "r6", "r7",
		  "r8", "r9");

	return ctx->ret;
}

#endif
