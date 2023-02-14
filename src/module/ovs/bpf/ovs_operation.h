#ifndef __MODULE_OVS_OPERATION__
#define __MODULE_OVS_OPERATION__

#include "ovs_common.h"

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
enum ovs_operation_type {
	OVS_OP_EXEC = 0,
	OVS_OP_PUT = 1,
};

/* Please keep in sync with its Rust counterpart in crate::module::ovs::bpf.rs. */
struct ovs_operation_event {
	/* enum ovs_operation_type */
	u8 type;
} __attribute__((packed));

#endif /* __MODULE_OVS_OPERATION__ */
