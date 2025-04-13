#ifndef __CORE_FILTERS_META_FILTER__
#define __CORE_FILTERS_META_FILTER__

#include <common_defs.h>

#define meta 0xdeadbeed
enum meta_filter_type {
	META = meta,
} __binding;

// BINDING_DEF(META, meta)

/* Please keep in sync with its Rust counterpart. */
#define __META_TARGET_MAX	32
static __hidden __binding const u32 META_TARGET_MAX = meta;
//BINDING_DEF(meta_target_max, META_TARGET_MAX)

#endif
