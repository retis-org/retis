#ifndef __COLLECTOR_DEV_COMMON__
#define __COLLECTOR_DEV_COMMON__

#include <common_defs.h>

enum dev_sections {
	SECTION_DEV = 1,
	SECTION_CORE_STAT,
} __binding;

BINDING_DEF(IFNAMSIZ, 16)

struct dev_event {
	u8 dev_name[IFNAMSIZ];
	u32 ifindex;
	u32 iif;
} __binding;

struct dev_core_stat_event {
	u32 offset;
} __binding;

#endif /* __COLLECTOR_DEV_COMMON__ */
