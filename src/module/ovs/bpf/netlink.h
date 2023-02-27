#ifndef __MODULE_OVS_NETLINK__
#define __MODULE_OVS_NETLINK__

#include <bpf/bpf_core_read.h>
#include <vmlinux.h>

/* Minimum set of netlink helpers. */

#define NLA_F_NESTED		(1 << 15)
#define NLA_F_NET_BYTEORDER	(1 << 14)
#define NLA_TYPE_MASK		~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

#define NLA_ALIGNTO		4
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN		((int) NLA_ALIGN(sizeof(struct nlattr)))

/**
 * nla_type - attribute type
 * @nla: netlink attribute
 */
static __always_inline int nla_type(const struct nlattr *nla)
{
	return BPF_CORE_READ(nla, nla_type) & NLA_TYPE_MASK;
}

/**
 * nla_data - head of payload
 * @nla: netlink attribute
 */
static __always_inline void *nla_data(const struct nlattr *nla)
{
	return (char *) nla + NLA_HDRLEN;
}

/**
 * nla_len - length of payload
 * @nla: netlink attribute
 */
static __always_inline int nla_len(const struct nlattr *nla)
{
	return BPF_CORE_READ(nla, nla_len) - NLA_HDRLEN;
}

#endif /* __MODULE_OVS_NETLINK__ */
