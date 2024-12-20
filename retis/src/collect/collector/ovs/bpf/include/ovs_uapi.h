#ifndef __MODULE_OVS_UAPI__
#define __MODULE_OVS_UAPI__

/* Some definitions from the uAPI that are not present in the BTF headers. */

/* From linux/netfilter/nf_nat.h. */
#define NF_NAT_RANGE_MAP_IPS			(1 << 0)
#define NF_NAT_RANGE_PROTO_SPECIFIED		(1 << 1)
#define NF_NAT_RANGE_PROTO_RANDOM		(1 << 2)
#define NF_NAT_RANGE_PERSISTENT			(1 << 3)
#define NF_NAT_RANGE_PROTO_RANDOM_FULLY		(1 << 4)
#define NF_NAT_RANGE_PROTO_OFFSET		(1 << 5)
#define NF_NAT_RANGE_NETMAP			(1 << 6)

#define NF_NAT_RANGE_PROTO_RANDOM_ALL		\
	(NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PROTO_RANDOM_FULLY)

#endif /* __MODULE_OVS_UAPI__ */
