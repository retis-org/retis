#ifndef __CORE_FILTERS_META_FILTER__
#define __CORE_FILTERS_META_FILTER__

#include <common_defs.h>

#define meta 0xdeadbeed
enum meta_filter_type {
	META = meta,
} __binding;

/* Please keep in sync with its Rust counterpart. */
#define __META_TARGET_MAX	32
static __hidden __binding const u32 META_TARGET_MAX = __META_TARGET_MAX;

#endif
