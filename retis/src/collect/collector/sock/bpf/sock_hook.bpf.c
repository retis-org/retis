#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <common.h>

struct sock_event {
	u32 inode;
	u16 type;
	u16 proto;
} __binding;


static __always_inline unsigned long sock_inode(struct socket *socket) {
	struct socket_alloc *alloc;

	if (!socket)
		return 0;

	alloc = container_of(socket, struct socket_alloc, socket);
	if (!alloc)
		return 0;

	return BPF_CORE_READ(alloc, vfs_inode.i_ino);
}

static __always_inline struct sock *get_sock_from_skb(struct sk_buff *skb)
{
	struct sock *sk;

	sk = BPF_CORE_READ(skb, sk);
	if (sk)
		return sk;

	return NULL;
}

DEFINE_HOOK_RAW(
	struct sock_event *e;
	struct sk_buff *skb;
	struct sock *sk;
	u32 inode = 0;

	skb = retis_get_sk_buff(ctx);
	if (!skb || !skb_is_tracked(skb))
		return 0;

	sk = get_sock_from_skb(skb);
	if (!sk) {
		sk = retis_get_sock(ctx);
		if (!sk)
			return 0;
	}

	struct socket *sk_socket = BPF_CORE_READ(sk, sk_socket);
	if (sk_socket) {
		inode = sock_inode(sk_socket);
	}

	e = get_event_section(event, COLLECTOR_SOCK, 0, sizeof(*e));
	if (!e)
		return 0;

	e->inode = inode;
	e->type = BPF_CORE_READ(sk, sk_type);
	e->proto = BPF_CORE_READ(sk, sk_protocol);

	return 0;
)

char __license[] SEC("license") = "GPL";

