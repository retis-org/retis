#ifndef __CORE_FILTERS_PACKETS_PACKET_FILTER__
#define __CORE_FILTERS_PACKETS_PACKET_FILTER__

/* Defines the context passed to the packet filtering
 * facility. Includes both input and output.
 * Keep in sync with its Rust counterpart in
 * core::filters::packets::ebpf.
 */
struct retis_filter_context {
	/* Input */
	char *data;		/* points to the beginning of the mac header. */
	unsigned int len;	/* linear length. */
	/* Output */
	unsigned int ret;	/* outcome of the match (zero if miss). */
} __attribute__((packed));

#endif
