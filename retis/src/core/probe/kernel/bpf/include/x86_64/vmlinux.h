#if !defined(__GENERIC_VMLINUX_H__) || defined(__VMLINUX_H__)
#error "Please do not include arch specific vmlinux header. Use #include <vmlinux.h>, instead."
#endif

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

 
#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

struct sk_buff;

struct net_device;



struct rb_node;

struct rb_node {
	long unsigned int          __rb_parent_color;    /*     0     8 */
	struct rb_node *           rb_right;             /*     8     8 */
	struct rb_node *           rb_left;              /*    16     8 */

	/* size: 24, cachelines: 1, members: 3 */
	/* last cacheline: 24 bytes */
};

struct list_head;

struct list_head {
	struct list_head *         next;                 /*     0     8 */
	struct list_head *         prev;                 /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};

struct llist_node;

struct llist_node {
	struct llist_node *        next;                 /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};


struct sock;

typedef long long int __s64;
typedef __s64 s64;
typedef s64 ktime_t;

typedef long long unsigned int __u64;
typedef __u64 u64;





typedef short unsigned int __u16;

typedef unsigned char __u8;

typedef __u16 u16;

typedef unsigned int __u32;
typedef __u32 __wsum;



typedef __u32 u32;

typedef __u16 __be16;









typedef unsigned int sk_buff_data_t;

typedef struct {
	int                        counter;              /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
} atomic_t;

struct refcount_struct {
	atomic_t                   refs;                 /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};
typedef struct refcount_struct refcount_t;

struct skb_ext;

struct sk_buff {
	union {
		struct {
			struct sk_buff * next;
			struct sk_buff * prev;
			union {
				struct net_device * dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node     rbnode;
		struct list_head   list;
		struct llist_node  ll_node;
	};
	struct sock *              sk;
	union {
		ktime_t            tstamp;
		u64                skb_mstamp_ns;
	};
	char                       cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void       (*destructor)(struct sk_buff *);
		};
		struct list_head   tcp_tsorted_anchor;
		long unsigned int  _sk_redir;
	};
	long unsigned int          _nfct;
	unsigned int               len;
	unsigned int               data_len;
	__u16                      mac_len;
	__u16                      hdr_len;
	__u16                      queue_mapping;
	__u8                       __cloned_offset[0];
	__u8                       cloned:1;
	__u8                       nohdr:1;
	__u8                       fclone:2;
	__u8                       peeked:1;
	__u8                       head_frag:1;
	__u8                       pfmemalloc:1;
	__u8                       pp_recycle:1;
	__u8                       active_extensions;
	union {
		struct {
			__u8       __pkt_type_offset[0];
			__u8       pkt_type:3;
			__u8       ignore_df:1;
			__u8       dst_pending_confirm:1;
			__u8       ip_summed:2;
			__u8       ooo_okay:1;
			__u8       __mono_tc_offset[0];
			__u8       tstamp_type:2;
			__u8       tc_at_ingress:1;
			__u8       tc_skip_classify:1;
			__u8       remcsum_offload:1;
			__u8       csum_complete_sw:1;
			__u8       csum_level:2;
			__u8       inner_protocol_type:1;
			__u8       l4_hash:1;
			__u8       sw_hash:1;
			__u8       wifi_acked_valid:1;
			__u8       wifi_acked:1;
			__u8       no_fcs:1;
			__u8       encapsulation:1;
			__u8       encap_hdr_csum:1;
			__u8       csum_valid:1;
			__u8       ndisc_nodetype:2;
			__u8       ipvs_property:1;
			__u8       nf_trace:1;
			__u8       offload_fwd_mark:1;
			__u8       offload_l3_fwd_mark:1;
			__u8       redirected:1;
			__u8       from_ingress:1;
			__u8       nf_skip_egress:1;
			__u8       decrypted:1;
			__u8       slow_gro:1;
			__u8       csum_not_inet:1;
			__u8       unreadable:1;
			__u16      tc_index;
			u16        alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16  csum_start;
					__u16  csum_offset;
				};
			};
			__u32      priority;
			int        skb_iif;
			__u32      hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16  vlan_tci;
				};
			};
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			__u32      secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16      inner_transport_header;
			__u16      inner_network_header;
			__u16      inner_mac_header;
			__be16     protocol;
			__u16      transport_header;
			__u16      network_header;
			__u16      mac_header;
		};
		struct {
			__u8       __pkt_type_offset[0];
			__u8       pkt_type:3;
			__u8       ignore_df:1;
			__u8       dst_pending_confirm:1;
			__u8       ip_summed:2;
			__u8       ooo_okay:1;
			__u8       __mono_tc_offset[0];
			__u8       tstamp_type:2;
			__u8       tc_at_ingress:1;
			__u8       tc_skip_classify:1;
			__u8       remcsum_offload:1;
			__u8       csum_complete_sw:1;
			__u8       csum_level:2;
			__u8       inner_protocol_type:1;
			__u8       l4_hash:1;
			__u8       sw_hash:1;
			__u8       wifi_acked_valid:1;
			__u8       wifi_acked:1;
			__u8       no_fcs:1;
			__u8       encapsulation:1;
			__u8       encap_hdr_csum:1;
			__u8       csum_valid:1;
			__u8       ndisc_nodetype:2;
			__u8       ipvs_property:1;
			__u8       nf_trace:1;
			__u8       offload_fwd_mark:1;
			__u8       offload_l3_fwd_mark:1;
			__u8       redirected:1;
			__u8       from_ingress:1;
			__u8       nf_skip_egress:1;
			__u8       decrypted:1;
			__u8       slow_gro:1;
			__u8       csum_not_inet:1;
			__u8       unreadable:1;
			__u16      tc_index;
			u16        alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16  csum_start;
					__u16  csum_offset;
				};
			};
			__u32      priority;
			int        skb_iif;
			__u32      hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16  vlan_tci;
				};
			};
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			__u32      secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16      inner_transport_header;
			__u16      inner_network_header;
			__u16      inner_mac_header;
			__be16     protocol;
			__u16      transport_header;
			__u16      network_header;
			__u16      mac_header;
		} headers;
	};
	sk_buff_data_t             tail;
	sk_buff_data_t             end;
	unsigned char *            head;
	unsigned char *            data;
	unsigned int               truesize;
	refcount_t                 users;
	struct skb_ext *           extensions;
};

typedef signed char __s8;
typedef __s8 s8;
typedef __s8 s8;

typedef short int __s16;
typedef __s16 s16;
typedef __s16 s16;

typedef int __s32;
typedef int __s32;

typedef __s32 s32;
typedef __s32 s32;

typedef _Bool bool;
typedef _Bool bool;

typedef struct {
	s64                        counter;              /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
} atomic64_t;

enum bpf_link_type {
	BPF_LINK_TYPE_UNSPEC         = 0,
	BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
	BPF_LINK_TYPE_TRACING        = 2,
	BPF_LINK_TYPE_CGROUP         = 3,
	BPF_LINK_TYPE_ITER           = 4,
	BPF_LINK_TYPE_NETNS          = 5,
	BPF_LINK_TYPE_XDP            = 6,
	BPF_LINK_TYPE_PERF_EVENT     = 7,
	BPF_LINK_TYPE_KPROBE_MULTI   = 8,
	BPF_LINK_TYPE_STRUCT_OPS     = 9,
	BPF_LINK_TYPE_NETFILTER      = 10,
	BPF_LINK_TYPE_TCX            = 11,
	BPF_LINK_TYPE_UPROBE_MULTI   = 12,
	BPF_LINK_TYPE_NETKIT         = 13,
	BPF_LINK_TYPE_SOCKMAP        = 14,
	__MAX_BPF_LINK_TYPE          = 15,
};

struct bpf_link_ops;

struct bpf_prog;

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS            = 0,
	BPF_CGROUP_INET_EGRESS             = 1,
	BPF_CGROUP_INET_SOCK_CREATE        = 2,
	BPF_CGROUP_SOCK_OPS                = 3,
	BPF_SK_SKB_STREAM_PARSER           = 4,
	BPF_SK_SKB_STREAM_VERDICT          = 5,
	BPF_CGROUP_DEVICE                  = 6,
	BPF_SK_MSG_VERDICT                 = 7,
	BPF_CGROUP_INET4_BIND              = 8,
	BPF_CGROUP_INET6_BIND              = 9,
	BPF_CGROUP_INET4_CONNECT           = 10,
	BPF_CGROUP_INET6_CONNECT           = 11,
	BPF_CGROUP_INET4_POST_BIND         = 12,
	BPF_CGROUP_INET6_POST_BIND         = 13,
	BPF_CGROUP_UDP4_SENDMSG            = 14,
	BPF_CGROUP_UDP6_SENDMSG            = 15,
	BPF_LIRC_MODE2                     = 16,
	BPF_FLOW_DISSECTOR                 = 17,
	BPF_CGROUP_SYSCTL                  = 18,
	BPF_CGROUP_UDP4_RECVMSG            = 19,
	BPF_CGROUP_UDP6_RECVMSG            = 20,
	BPF_CGROUP_GETSOCKOPT              = 21,
	BPF_CGROUP_SETSOCKOPT              = 22,
	BPF_TRACE_RAW_TP                   = 23,
	BPF_TRACE_FENTRY                   = 24,
	BPF_TRACE_FEXIT                    = 25,
	BPF_MODIFY_RETURN                  = 26,
	BPF_LSM_MAC                        = 27,
	BPF_TRACE_ITER                     = 28,
	BPF_CGROUP_INET4_GETPEERNAME       = 29,
	BPF_CGROUP_INET6_GETPEERNAME       = 30,
	BPF_CGROUP_INET4_GETSOCKNAME       = 31,
	BPF_CGROUP_INET6_GETSOCKNAME       = 32,
	BPF_XDP_DEVMAP                     = 33,
	BPF_CGROUP_INET_SOCK_RELEASE       = 34,
	BPF_XDP_CPUMAP                     = 35,
	BPF_SK_LOOKUP                      = 36,
	BPF_XDP                            = 37,
	BPF_SK_SKB_VERDICT                 = 38,
	BPF_SK_REUSEPORT_SELECT            = 39,
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE = 40,
	BPF_PERF_EVENT                     = 41,
	BPF_TRACE_KPROBE_MULTI             = 42,
	BPF_LSM_CGROUP                     = 43,
	BPF_STRUCT_OPS                     = 44,
	BPF_NETFILTER                      = 45,
	BPF_TCX_INGRESS                    = 46,
	BPF_TCX_EGRESS                     = 47,
	BPF_TRACE_UPROBE_MULTI             = 48,
	BPF_CGROUP_UNIX_CONNECT            = 49,
	BPF_CGROUP_UNIX_SENDMSG            = 50,
	BPF_CGROUP_UNIX_RECVMSG            = 51,
	BPF_CGROUP_UNIX_GETPEERNAME        = 52,
	BPF_CGROUP_UNIX_GETSOCKNAME        = 53,
	BPF_NETKIT_PRIMARY                 = 54,
	BPF_NETKIT_PEER                    = 55,
	BPF_TRACE_KPROBE_SESSION           = 56,
	BPF_TRACE_UPROBE_SESSION           = 57,
	BPF_TRACE_FSESSION                 = 58,
	__MAX_BPF_ATTACH_TYPE              = 59,
};

struct callback_head;

struct callback_head {
	struct callback_head *     next;                 /*     0     8 */
	void                       (*func)(struct callback_head *); /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};

typedef atomic64_t atomic_long_t;


struct work_struct;

typedef void (*work_func_t)(struct work_struct *);

struct work_struct {
	atomic_long_t              data;                 /*     0     8 */
	struct list_head           entry;                /*     8    16 */
	work_func_t                func;                 /*    24     8 */

	/* size: 32, cachelines: 1, members: 3 */
	/* last cacheline: 32 bytes */
};


struct bpf_link {
	atomic64_t                 refcnt;               /*     0     8 */
	u32                        id;                   /*     8     4 */
	enum bpf_link_type         type;                 /*    12     4 */
	const struct bpf_link_ops  * ops;                /*    16     8 */
	struct bpf_prog *          prog;                 /*    24     8 */
	u32                        flags;                /*    32     4 */
	enum bpf_attach_type       attach_type;          /*    36     4 */
	union {
		struct callback_head rcu;                /*    40    16 */
		struct work_struct work;                 /*    40    32 */
	};                                               /*    40    32 */
	/* --- cacheline 1 boundary (64 bytes) was 8 bytes ago --- */
	bool                       sleepable;            /*    72     1 */

	/* size: 80, cachelines: 2, members: 9 */
	/* padding: 7 */
	/* last cacheline: 16 bytes */
};

typedef long unsigned int __kernel_ulong_t;
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_size_t size_t;

struct fprobe;
struct ftrace_regs;

typedef int (*fprobe_entry_cb)(struct fprobe *, long unsigned int, long unsigned int, struct ftrace_regs *, void *);

typedef void (*fprobe_exit_cb)(struct fprobe *, long unsigned int, long unsigned int, struct ftrace_regs *, void *);

struct fprobe_hlist;

struct fprobe {
	long unsigned int          nmissed;              /*     0     8 */
	unsigned int               flags;                /*     8     4 */

	/* XXX 4 bytes hole, try to pack */

	size_t                     entry_data_size;      /*    16     8 */
	fprobe_entry_cb            entry_handler;        /*    24     8 */
	fprobe_exit_cb             exit_handler;         /*    32     8 */
	struct fprobe_hlist *      hlist_array;          /*    40     8 */

	/* size: 48, cachelines: 1, members: 6 */
	/* sum members: 44, holes: 1, sum holes: 4 */
	/* last cacheline: 48 bytes */
};

struct module;

struct bpf_kprobe_multi_link {
	struct bpf_link            link;
	struct fprobe              fp;
	long unsigned int *        addrs;
	u64 *                      cookies;
	u32                        cnt;
	u32                        mods_cnt;
	struct module * *          mods;
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC                           = 0,
	BPF_MAP_TYPE_HASH                             = 1,
	BPF_MAP_TYPE_ARRAY                            = 2,
	BPF_MAP_TYPE_PROG_ARRAY                       = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY                 = 4,
	BPF_MAP_TYPE_PERCPU_HASH                      = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY                     = 6,
	BPF_MAP_TYPE_STACK_TRACE                      = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY                     = 8,
	BPF_MAP_TYPE_LRU_HASH                         = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH                  = 10,
	BPF_MAP_TYPE_LPM_TRIE                         = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS                    = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS                     = 13,
	BPF_MAP_TYPE_DEVMAP                           = 14,
	BPF_MAP_TYPE_SOCKMAP                          = 15,
	BPF_MAP_TYPE_CPUMAP                           = 16,
	BPF_MAP_TYPE_XSKMAP                           = 17,
	BPF_MAP_TYPE_SOCKHASH                         = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED        = 19,
	BPF_MAP_TYPE_CGROUP_STORAGE                   = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY              = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE            = 21,
	BPF_MAP_TYPE_QUEUE                            = 22,
	BPF_MAP_TYPE_STACK                            = 23,
	BPF_MAP_TYPE_SK_STORAGE                       = 24,
	BPF_MAP_TYPE_DEVMAP_HASH                      = 25,
	BPF_MAP_TYPE_STRUCT_OPS                       = 26,
	BPF_MAP_TYPE_RINGBUF                          = 27,
	BPF_MAP_TYPE_INODE_STORAGE                    = 28,
	BPF_MAP_TYPE_TASK_STORAGE                     = 29,
	BPF_MAP_TYPE_BLOOM_FILTER                     = 30,
	BPF_MAP_TYPE_USER_RINGBUF                     = 31,
	BPF_MAP_TYPE_CGRP_STORAGE                     = 32,
	BPF_MAP_TYPE_ARENA                            = 33,
	BPF_MAP_TYPE_INSN_ARRAY                       = 34,
	__MAX_BPF_MAP_TYPE                            = 35,
};


struct bpf_raw_event_map;

struct bpf_raw_tp_link {
	struct bpf_link            link;
	struct bpf_raw_event_map * btp;
	u64                        cookie;
};

struct bpf_raw_tracepoint_args {
	__u64                      args[0];
};

typedef __u8 u8;
typedef u8 kprobe_opcode_t;
typedef u8 kprobe_opcode_t;

struct fred_cs {
	u64                        cs:16;                /*     0: 0  2 */
	u64                        sl:2;                 /*     0:16  3 */
	u64                        wfe:1;                /*     0:18  3 */

	/* size: 8, cachelines: 1, members: 3 */
	/* bit_padding: 45 bits */
	/* last cacheline: 8 bytes */
};


struct fred_ss {
	u64                        ss:16;                /*     0: 0  2 */
	u64                        sti:1;                /*     0:16  3 */
	u64                        swevent:1;            /*     0:17  3 */
	u64                        nmi:1;                /*     0:18  3 */

	/* XXX 13 bits hole, try to pack */
	u64                        :13;

	u64                        vector:8;             /*     0:32  5 */

	/* XXX 8 bits hole, try to pack */
	u64                        :8;

	u64                        type:4;               /*     0:48  7 */

	/* XXX 4 bits hole, try to pack */
	u64                        :4;

	u64                        enclave:1;            /*     0:56  8 */
	u64                        l:1;                  /*     0:57  8 */
	u64                        nested:1;             /*     0:58  8 */

	/* XXX 1 bit hole, try to pack */
	u64                        :1;

	u64                        insnlen:4;            /*     0:60  8 */

	/* size: 8, cachelines: 1, members: 10 */
	/* sum bitfield members: 38 bits, bit holes: 4, sum bit holes: 26 bits */
	/* last cacheline: 8 bytes */
};


struct pt_regs {
	long unsigned int          r15;
	long unsigned int          r14;
	long unsigned int          r13;
	long unsigned int          r12;
	long unsigned int          bp;
	long unsigned int          bx;
	long unsigned int          r11;
	long unsigned int          r10;
	long unsigned int          r9;
	long unsigned int          r8;
	long unsigned int          ax;
	long unsigned int          cx;
	long unsigned int          dx;
	long unsigned int          si;
	long unsigned int          di;
	long unsigned int          orig_ax;
	long unsigned int          ip;
	union {
		u16                cs;
		u64                csx;
		struct fred_cs     fred_cs;
	};
	long unsigned int          flags;
	long unsigned int          sp;
	union {
		u16                ss;
		u64                ssx;
		struct fred_ss     fred_ss;
	};
};

struct nf_conntrack {
	refcount_t                 use;                  /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};




struct qspinlock {
	union {
		atomic_t           val;                  /*     0     4 */
		struct {
			u8         locked;               /*     0     1 */
			u8         pending;              /*     1     1 */
		};                                       /*     0     2 */
		struct {
			u16        locked_pending;       /*     0     2 */
			u16        tail;                 /*     2     2 */
		};                                       /*     0     4 */
	};                                               /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};
typedef struct qspinlock arch_spinlock_t;

struct raw_spinlock {
	arch_spinlock_t            raw_lock;             /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};


struct spinlock {
	union {
		struct raw_spinlock rlock;               /*     0     4 */
	};                                               /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};
typedef struct spinlock spinlock_t;

struct nf_conntrack_zone {
	u16                        id;                   /*     0     2 */
	u8                         flags;                /*     2     1 */
	u8                         dir;                  /*     3     1 */

	/* size: 4, cachelines: 1, members: 3 */
	/* last cacheline: 4 bytes */
};

struct hlist_nulls_node;

struct hlist_nulls_node {
	struct hlist_nulls_node *  next;                 /*     0     8 */
	struct hlist_nulls_node * * pprev;               /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};

typedef __u32 __be32;

struct in_addr {
	__be32                     s_addr;               /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};


struct in6_addr {
	union {
		__u8               u6_addr8[16];         /*     0    16 */
		__be16             u6_addr16[8];         /*     0    16 */
		__be32             u6_addr32[4];         /*     0    16 */
	} in6_u;                                         /*     0    16 */

	/* size: 16, cachelines: 1, members: 1 */
	/* last cacheline: 16 bytes */
};

union nf_inet_addr {
	__u32                      all[4];             /*     0    16 */
	__be32                     ip;                 /*     0     4 */
	__be32                     ip6[4];             /*     0    16 */
	struct in_addr             in;                 /*     0     4 */
	struct in6_addr            in6;                /*     0    16 */
};







union nf_conntrack_man_proto {
	__be16                     all;                /*     0     2 */
	struct {
		__be16             port;               /*     0     2 */
	} tcp;                                         /*     0     2 */
	struct {
		__be16             port;               /*     0     2 */
	} udp;                                         /*     0     2 */
	struct {
		__be16             id;                 /*     0     2 */
	} icmp;                                        /*     0     2 */
	struct {
		__be16             port;               /*     0     2 */
	} dccp;                                        /*     0     2 */
	struct {
		__be16             port;               /*     0     2 */
	} sctp;                                        /*     0     2 */
	struct {
		__be16             key;                /*     0     2 */
	} gre;                                         /*     0     2 */
};

typedef u16 u_int16_t;

struct nf_conntrack_man {
	union nf_inet_addr         u3;                   /*     0    16 */
	union nf_conntrack_man_proto u;                  /*    16     2 */
	u_int16_t                  l3num;                /*    18     2 */

	/* size: 20, cachelines: 1, members: 3 */
	/* last cacheline: 20 bytes */
};




typedef u8 u_int8_t;








struct nf_conntrack_tuple {
	struct nf_conntrack_man    src;                  /*     0    20 */
	struct {
		union nf_inet_addr u3;                   /*    20    16 */
		union {
			__be16     all;                  /*    36     2 */
			struct {
				__be16 port;             /*    36     2 */
			} tcp;                           /*    36     2 */
			struct {
				__be16 port;             /*    36     2 */
			} udp;                           /*    36     2 */
			struct {
				u_int8_t type;           /*    36     1 */
				u_int8_t code;           /*    37     1 */
			} icmp;                          /*    36     2 */
			struct {
				__be16 port;             /*    36     2 */
			} dccp;                          /*    36     2 */
			struct {
				__be16 port;             /*    36     2 */
			} sctp;                          /*    36     2 */
			struct {
				__be16 key;              /*    36     2 */
			} gre;                           /*    36     2 */
		} u;                                     /*    36     2 */
		u_int8_t           protonum;             /*    38     1 */
		struct {
		} __nfct_hash_offsetend;                 /*    39     0 */
		u_int8_t           dir;                  /*    39     1 */
	} dst;                                           /*    20    20 */

	/* size: 40, cachelines: 1, members: 2 */
	/* last cacheline: 40 bytes */
};

struct nf_conntrack_tuple_hash {
	struct hlist_nulls_node    hnnode;               /*     0    16 */
	struct nf_conntrack_tuple  tuple;                /*    16    40 */

	/* size: 56, cachelines: 1, members: 2 */
	/* last cacheline: 56 bytes */
};

struct net;

typedef struct {
	struct net *               net;                  /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
} possible_net_t;

struct hlist_node;

struct hlist_node {
	struct hlist_node *        next;                 /*     0     8 */
	struct hlist_node * *      pprev;                /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};


struct nf_conn;

typedef u32 u_int32_t;

struct nf_ct_ext;

enum sctp_conntrack {
	SCTP_CONNTRACK_NONE              = 0,
	SCTP_CONNTRACK_CLOSED            = 1,
	SCTP_CONNTRACK_COOKIE_WAIT       = 2,
	SCTP_CONNTRACK_COOKIE_ECHOED     = 3,
	SCTP_CONNTRACK_ESTABLISHED       = 4,
	SCTP_CONNTRACK_SHUTDOWN_SENT     = 5,
	SCTP_CONNTRACK_SHUTDOWN_RECD     = 6,
	SCTP_CONNTRACK_SHUTDOWN_ACK_SENT = 7,
	SCTP_CONNTRACK_HEARTBEAT_SENT    = 8,
	SCTP_CONNTRACK_HEARTBEAT_ACKED   = 9,
	SCTP_CONNTRACK_MAX               = 10,
};

struct ip_ct_sctp {
	enum sctp_conntrack        state;                /*     0     4 */
	__be32                     vtag[2];              /*     4     8 */
	u8                         init[2];              /*    12     2 */
	u8                         last_dir;             /*    14     1 */
	u8                         flags;                /*    15     1 */

	/* size: 16, cachelines: 1, members: 5 */
	/* last cacheline: 16 bytes */
};

struct ip_ct_tcp_state {
	u_int32_t                  td_end;               /*     0     4 */
	u_int32_t                  td_maxend;            /*     4     4 */
	u_int32_t                  td_maxwin;            /*     8     4 */
	u_int32_t                  td_maxack;            /*    12     4 */
	u_int8_t                   td_scale;             /*    16     1 */
	u_int8_t                   flags;                /*    17     1 */

	/* size: 20, cachelines: 1, members: 6 */
	/* padding: 2 */
	/* last cacheline: 20 bytes */
};

struct ip_ct_tcp {
	struct ip_ct_tcp_state     seen[2];              /*     0    40 */
	u_int8_t                   state;                /*    40     1 */
	u_int8_t                   last_dir;             /*    41     1 */
	u_int8_t                   retrans;              /*    42     1 */
	u_int8_t                   last_index;           /*    43     1 */
	u_int32_t                  last_seq;             /*    44     4 */
	u_int32_t                  last_ack;             /*    48     4 */
	u_int32_t                  last_end;             /*    52     4 */
	u_int16_t                  last_win;             /*    56     2 */
	u_int8_t                   last_wscale;          /*    58     1 */
	u_int8_t                   last_flags;           /*    59     1 */

	/* size: 60, cachelines: 1, members: 11 */
	/* last cacheline: 60 bytes */
};

struct nf_ct_udp {
	long unsigned int          stream_ts;            /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};

struct nf_ct_gre {
	unsigned int               stream_timeout;       /*     0     4 */
	unsigned int               timeout;              /*     4     4 */

	/* size: 8, cachelines: 1, members: 2 */
	/* last cacheline: 8 bytes */
};

union nf_conntrack_proto {
	struct ip_ct_sctp          sctp;               /*     0    16 */
	struct ip_ct_tcp           tcp;                /*     0    60 */
	struct nf_ct_udp           udp;                /*     0     8 */
	struct nf_ct_gre           gre;                /*     0     8 */
	unsigned int               tmpl_padto;         /*     0     4 */
};

struct nf_conn {
	struct nf_conntrack        ct_general;
	spinlock_t                 lock;
	u32                        timeout;
	struct nf_conntrack_zone   zone;
	struct nf_conntrack_tuple_hash tuplehash[2];
	long unsigned int          status;
	possible_net_t             ct_net;
	struct hlist_node          nat_bysource;
	struct {
	} __nfct_init_offset;
	struct nf_conn *           master;
	u_int32_t                  mark;
	u_int32_t                  secmark;
	struct nf_ct_ext *         ext;
	union nf_conntrack_proto   proto;
};

struct nf_conn_labels {
	long unsigned int          bits[2];
};

enum ip_conntrack_dir {
	IP_CT_DIR_ORIGINAL = 0,
	IP_CT_DIR_REPLY    = 1,
	IP_CT_DIR_MAX      = 2,
};

struct nf_ct_ext {
	u8                         offset[10];
	u8                         len;
	unsigned int               gen_id;
	char                       data[];
};

enum nf_ct_ext_id {
	NF_CT_EXT_HELPER   = 0,
	NF_CT_EXT_NAT      = 1,
	NF_CT_EXT_SEQADJ   = 2,
	NF_CT_EXT_ACCT     = 3,
	NF_CT_EXT_ECACHE   = 4,
	NF_CT_EXT_TSTAMP   = 5,
	NF_CT_EXT_TIMEOUT  = 6,
	NF_CT_EXT_LABELS   = 7,
	NF_CT_EXT_SYNPROXY = 8,
	NF_CT_EXT_ACT_CT   = 9,
	NF_CT_EXT_NUM      = 10,
};



struct sk_buff;
struct nf_hook_state;

typedef unsigned int (nf_hookfn)(void *, struct sk_buff *, const struct nf_hook_state  *);

enum nf_hook_ops_type {
	NF_HOOK_OP_UNDEFINED = 0,
	NF_HOOK_OP_NF_TABLES = 1,
	NF_HOOK_OP_BPF       = 2,
	NF_HOOK_OP_NFT_FT    = 3,
};

struct nf_hook_ops {
	struct list_head           list;                 /*     0    16 */
	struct callback_head       rcu;                  /*    16    16 */
	nf_hookfn *                hook;                 /*    32     8 */
	struct net_device *        dev;                  /*    40     8 */
	void *                     priv;                 /*    48     8 */
	u8                         pf;                   /*    56     1 */

	/* Bitfield combined with previous fields */

	enum nf_hook_ops_type      hook_ops_type:8;      /*    56: 8  2 */

	/* XXX 16 bits hole, try to pack */

	unsigned int               hooknum;              /*    60     4 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	int                        priority;             /*    64     4 */

	/* size: 72, cachelines: 2, members: 9 */
	/* sum members: 65 */
	/* sum bitfield members: 8 bits, bit holes: 1, sum bit holes: 16 bits */
	/* padding: 4 */
	/* last cacheline: 8 bytes */
};


struct nft_chain_type;

struct nft_stats;

struct nft_rule_blob;



struct rhash_head;

struct rhash_head {
	struct rhash_head *        next;                 /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};

struct rhlist_head;

struct rhlist_head {
	struct rhash_head          rhead;                /*     0     8 */
	struct rhlist_head *       next;                 /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};

struct nft_table;

struct nft_chain_validate_state {
	u8                         hook_mask[3];         /*     0     3 */
	u8                         depth;                /*     3     1 */

	/* size: 4, cachelines: 1, members: 2 */
	/* last cacheline: 4 bytes */
};

struct nft_chain {
	struct nft_rule_blob *     blob_gen_0;           /*     0     8 */
	struct nft_rule_blob *     blob_gen_1;           /*     8     8 */
	struct list_head           rules;                /*    16    16 */
	struct list_head           list;                 /*    32    16 */
	struct rhlist_head         rhlhead;              /*    48    16 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	struct nft_table *         table;                /*    64     8 */
	u64                        handle;               /*    72     8 */
	u32                        use;                  /*    80     4 */
	u8                         flags:5;              /*    84: 0  1 */
	u8                         bound:1;              /*    84: 5  1 */
	u8                         genmask:2;            /*    84: 6  1 */

	/* XXX 3 bytes hole, try to pack */

	char *                     name;                 /*    88     8 */
	u16                        udlen;                /*    96     2 */

	/* XXX 6 bytes hole, try to pack */

	u8 *                       udata;                /*   104     8 */
	struct nft_rule_blob *     blob_next;            /*   112     8 */
	struct nft_chain_validate_state vstate;          /*   120     4 */

	/* size: 128, cachelines: 2, members: 16 */
	/* sum members: 114, holes: 2, sum holes: 9 */
	/* sum bitfield members: 8 bits (1 bytes) */
	/* padding: 4 */
};


struct flow_block {
	struct list_head           cb_list;              /*     0    16 */

	/* size: 16, cachelines: 1, members: 1 */
	/* last cacheline: 16 bytes */
};

struct nft_base_chain {
	struct nf_hook_ops         ops;
	struct list_head           hook_list;
	const struct nft_chain_type  * type;
	u8                         policy;
	u8                         flags;
	struct nft_stats *         stats;
	struct nft_chain           chain;
	struct flow_block          flow_block;
};

struct nft_pktinfo {
	struct sk_buff *           skb;
	const struct nf_hook_state  * state;
	u8                         flags;
	u8                         tprot;
	u16                        fragoff;
	u16                        thoff;
	u16                        inneroff;
};


struct nft_rule {
	struct list_head           list;
	u64                        handle:42;
	u64                        genmask:2;
	u64                        dlen:12;
	u64                        udata:1;
	unsigned char              data[];
};

struct nft_rule_dp {
	u64                        is_last:1;
	u64                        dlen:12;
	u64                        handle:42;
	unsigned char              data[] __attribute__((__aligned__(2)));
};



struct nft_chain;

struct nft_rule_dp_last {
	struct nft_rule_dp         end;
	struct callback_head       h;
	struct nft_rule_blob *     blob;
	const struct nft_chain  *  chain;
};


struct bucket_table;

typedef u32 (*rht_hashfn_t)(const void  *, u32, u32);

typedef u32 (*rht_obj_hashfn_t)(const void  *, u32, u32);

struct rhashtable_compare_arg;

typedef int (*rht_obj_cmpfn_t)(struct rhashtable_compare_arg *, const void  *);

struct rhashtable_params {
	u16                        nelem_hint;           /*     0     2 */
	u16                        key_len;              /*     2     2 */
	u16                        key_offset;           /*     4     2 */
	u16                        head_offset;          /*     6     2 */
	unsigned int               max_size;             /*     8     4 */
	u16                        min_size;             /*    12     2 */
	bool                       automatic_shrinking;  /*    14     1 */

	/* XXX 1 byte hole, try to pack */

	rht_hashfn_t               hashfn;               /*    16     8 */
	rht_obj_hashfn_t           obj_hashfn;           /*    24     8 */
	rht_obj_cmpfn_t            obj_cmpfn;            /*    32     8 */

	/* size: 40, cachelines: 1, members: 10 */
	/* sum members: 39, holes: 1, sum holes: 1 */
	/* last cacheline: 40 bytes */
};


typedef struct raw_spinlock raw_spinlock_t;

struct optimistic_spin_queue {
	atomic_t                   tail;                 /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};


struct mutex {
	atomic_long_t              owner;                /*     0     8 */
	raw_spinlock_t             wait_lock;            /*     8     4 */
	struct optimistic_spin_queue osq;                /*    12     4 */
	struct list_head           wait_list;            /*    16    16 */

	/* size: 32, cachelines: 1, members: 4 */
	/* last cacheline: 32 bytes */
};

struct rhashtable {
	struct bucket_table *      tbl;                  /*     0     8 */
	unsigned int               key_len;              /*     8     4 */
	unsigned int               max_elems;            /*    12     4 */
	struct rhashtable_params   p;                    /*    16    40 */

	/* XXX last struct has 1 hole */

	bool                       rhlist;               /*    56     1 */

	/* XXX 7 bytes hole, try to pack */

	/* --- cacheline 1 boundary (64 bytes) --- */
	struct work_struct         run_work;             /*    64    32 */
	struct mutex               mutex;                /*    96    32 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	spinlock_t                 lock;                 /*   128     4 */
	atomic_t                   nelems;               /*   132     4 */

	/* size: 136, cachelines: 3, members: 9 */
	/* sum members: 129, holes: 1, sum holes: 7 */
	/* member types with holes: 1, total: 1 */
	/* last cacheline: 8 bytes */
};

struct rhltable {
	struct rhashtable          ht;                   /*     0   136 */

	/* XXX last struct has 1 hole */

	/* size: 136, cachelines: 3, members: 1 */
	/* member types with holes: 1, total: 1 */
	/* last cacheline: 8 bytes */
};





struct nft_table {
	struct list_head           list;
	struct rhltable            chains_ht;
	struct list_head           chains;
	struct list_head           sets;
	struct list_head           objects;
	struct list_head           flowtables;
	u64                        hgenerator;
	u64                        handle;
	u32                        use;
	u16                        family:6;
	u16                        flags:8;
	u16                        genmask:2;
	u32                        nlpid;
	char *                     name;
	u16                        udlen;
	u8 *                       udata;
	u8                         validate_state;
};

enum nft_trace_types {
	NFT_TRACETYPE_UNSPEC = 0,
	NFT_TRACETYPE_POLICY = 1,
	NFT_TRACETYPE_RETURN = 2,
	NFT_TRACETYPE_RULE   = 3,
	__NFT_TRACETYPE_MAX  = 4,
};

struct nft_base_chain;

struct nft_traceinfo {
	bool                       trace;
	bool                       nf_trace;
	bool                       packet_dumped;
	enum nft_trace_types       type:8;
	u32                        skbid;
	const struct nft_base_chain  * basechain;
};

struct nft_verdict {
	u32                        code;
	struct nft_chain *         chain;
};

enum nft_verdicts {
	NFT_CONTINUE = -1,
	NFT_BREAK    = -2,
	NFT_JUMP     = -3,
	NFT_GOTO     = -4,
	NFT_RETURN   = -5,
};

struct ip_tunnel_info;

struct nlattr;

struct dp_upcall_info {
	struct ip_tunnel_info *    egress_tun_info;
	const struct nlattr  *     userdata;
	const struct nlattr  *     actions;
	int                        actions_len;
	u32                        portid;
	u8                         cmd;
	u16                        mru;
};

enum ovs_action_attr {
	OVS_ACTION_ATTR_UNSPEC        = 0,
	OVS_ACTION_ATTR_OUTPUT        = 1,
	OVS_ACTION_ATTR_USERSPACE     = 2,
	OVS_ACTION_ATTR_SET           = 3,
	OVS_ACTION_ATTR_PUSH_VLAN     = 4,
	OVS_ACTION_ATTR_POP_VLAN      = 5,
	OVS_ACTION_ATTR_SAMPLE        = 6,
	OVS_ACTION_ATTR_RECIRC        = 7,
	OVS_ACTION_ATTR_HASH          = 8,
	OVS_ACTION_ATTR_PUSH_MPLS     = 9,
	OVS_ACTION_ATTR_POP_MPLS      = 10,
	OVS_ACTION_ATTR_SET_MASKED    = 11,
	OVS_ACTION_ATTR_CT            = 12,
	OVS_ACTION_ATTR_TRUNC         = 13,
	OVS_ACTION_ATTR_PUSH_ETH      = 14,
	OVS_ACTION_ATTR_POP_ETH       = 15,
	OVS_ACTION_ATTR_CT_CLEAR      = 16,
	OVS_ACTION_ATTR_PUSH_NSH      = 17,
	OVS_ACTION_ATTR_POP_NSH       = 18,
	OVS_ACTION_ATTR_METER         = 19,
	OVS_ACTION_ATTR_CLONE         = 20,
	OVS_ACTION_ATTR_CHECK_PKT_LEN = 21,
	OVS_ACTION_ATTR_ADD_MPLS      = 22,
	OVS_ACTION_ATTR_DEC_TTL       = 23,
	OVS_ACTION_ATTR_DROP          = 24,
	OVS_ACTION_ATTR_PSAMPLE       = 25,
	__OVS_ACTION_ATTR_MAX         = 26,
	OVS_ACTION_ATTR_SET_TO_MASKED = 27,
};

struct nf_conntrack_helper;


struct nf_conn;

struct md_mark {
	u32                        value;                /*     0     4 */
	u32                        mask;                 /*     4     4 */

	/* size: 8, cachelines: 1, members: 2 */
	/* last cacheline: 8 bytes */
};


struct ovs_key_ct_labels {
	union {
		__u8               ct_labels[16];        /*     0    16 */
		__u32              ct_labels_32[4];      /*     0    16 */
	};                                               /*     0    16 */

	/* size: 16, cachelines: 1, members: 1 */
	/* last cacheline: 16 bytes */
};


struct md_labels {
	struct ovs_key_ct_labels   value;                /*     0    16 */
	struct ovs_key_ct_labels   mask;                 /*    16    16 */

	/* size: 32, cachelines: 1, members: 2 */
	/* last cacheline: 32 bytes */
};

struct nf_ct_timeout;






struct nf_nat_range2 {
	unsigned int               flags;                /*     0     4 */
	union nf_inet_addr         min_addr;             /*     4    16 */
	union nf_inet_addr         max_addr;             /*    20    16 */
	union nf_conntrack_man_proto min_proto;          /*    36     2 */
	union nf_conntrack_man_proto max_proto;          /*    38     2 */
	union nf_conntrack_man_proto base_proto;         /*    40     2 */

	/* size: 44, cachelines: 1, members: 6 */
	/* padding: 2 */
	/* last cacheline: 44 bytes */
};

struct ovs_conntrack_info {
	struct nf_conntrack_helper * helper;
	struct nf_conntrack_zone   zone;
	struct nf_conn *           ct;
	u8                         commit:1;
	u8                         nat:3;
	u8                         force:1;
	u8                         have_eventmask:1;
	u16                        family;
	u32                        eventmask;
	struct md_mark             mark;
	struct md_labels           labels;
	char                       timeout[32];
	struct nf_ct_timeout *     nf_ct_timeout;
	struct nf_nat_range2       range;
};

enum ovs_ct_nat {
	OVS_CT_NAT     = 1,
	OVS_CT_SRC_NAT = 2,
	OVS_CT_DST_NAT = 4,
};

struct nlattr {
	__u16                      nla_len;
	__u16                      nla_type;
};





typedef __u64 __be64;






struct ip_tunnel_key {
	__be64                     tun_id;               /*     0     8 */
	union {
		struct {
			__be32     src;                  /*     8     4 */
			__be32     dst;                  /*    12     4 */
		} ipv4;                                  /*     8     8 */
		struct {
			struct in6_addr src;             /*     8    16 */
			struct in6_addr dst;             /*    24    16 */
		} ipv6;                                  /*     8    32 */
	} u;                                             /*     8    32 */
	long unsigned int          tun_flags[1];         /*    40     8 */
	__be32                     label;                /*    48     4 */
	u32                        nhid;                 /*    52     4 */
	u8                         tos;                  /*    56     1 */
	u8                         ttl;                  /*    57     1 */
	__be16                     tp_src;               /*    58     2 */
	__be16                     tp_dst;               /*    60     2 */
	__u8                       flow_flags;           /*    62     1 */

	/* size: 64, cachelines: 1, members: 10 */
	/* padding: 1 */
};


struct vlan_head {
	__be16                     tpid;                 /*     0     2 */
	__be16                     tci;                  /*     2     2 */

	/* size: 4, cachelines: 1, members: 2 */
	/* last cacheline: 4 bytes */
};


















struct ovs_nsh_key_base {
	__u8                       flags;                /*     0     1 */
	__u8                       ttl;                  /*     1     1 */
	__u8                       mdtype;               /*     2     1 */
	__u8                       np;                   /*     3     1 */
	__be32                     path_hdr;             /*     4     4 */

	/* size: 8, cachelines: 1, members: 5 */
	/* last cacheline: 8 bytes */
};

struct ovs_key_nsh {
	struct ovs_nsh_key_base    base;                 /*     0     8 */
	__be32                     context[4];           /*     8    16 */

	/* size: 24, cachelines: 1, members: 2 */
	/* last cacheline: 24 bytes */
};





struct sw_flow_key {
	u8                         tun_opts[255];        /*     0   255 */
	/* --- cacheline 3 boundary (192 bytes) was 63 bytes ago --- */
	u8                         tun_opts_len;         /*   255     1 */
	/* --- cacheline 4 boundary (256 bytes) --- */
	struct ip_tunnel_key       tun_key;              /*   256    64 */

	/* XXX last struct has 1 byte of padding */

	/* --- cacheline 5 boundary (320 bytes) --- */
	struct {
		u32                priority;             /*   320     4 */
		u32                skb_mark;             /*   324     4 */
		u16                in_port;              /*   328     2 */
	} __attribute__((__packed__)) phy;               /*   320    10 */
	u8                         mac_proto;            /*   330     1 */
	u8                         tun_proto;            /*   331     1 */
	u32                        ovs_flow_hash;        /*   332     4 */
	u32                        recirc_id;            /*   336     4 */
	struct {
		u8                 src[6];               /*   340     6 */
		u8                 dst[6];               /*   346     6 */
		struct vlan_head   vlan;                 /*   352     4 */
		struct vlan_head   cvlan;                /*   356     4 */
		__be16             type;                 /*   360     2 */
	} eth;                                           /*   340    22 */
	u8                         ct_state;             /*   362     1 */
	u8                         ct_orig_proto;        /*   363     1 */
	union {
		struct {
			u8         proto;                /*   364     1 */
			u8         tos;                  /*   365     1 */
			u8         ttl;                  /*   366     1 */
			u8         frag;                 /*   367     1 */
		} ip;                                    /*   364     4 */
	};                                               /*   364     4 */
	u16                        ct_zone;              /*   368     2 */
	struct {
		__be16             src;                  /*   370     2 */
		__be16             dst;                  /*   372     2 */
		__be16             flags;                /*   374     2 */
	} tp;                                            /*   370     6 */
	union {
		struct {
			struct {
				__be32 src;              /*   376     4 */
				__be32 dst;              /*   380     4 */
			} addr;                          /*   376     8 */
			/* --- cacheline 6 boundary (384 bytes) --- */
			union {
				struct {
					__be32 src;      /*   384     4 */
					__be32 dst;      /*   388     4 */
				} ct_orig;               /*   384     8 */
				struct {
					u8     sha[6];   /*   384     6 */
					u8     tha[6];   /*   390     6 */
				} arp;                   /*   384    12 */
			};                               /*   384    12 */
		} ipv4;                                  /*   376    20 */
		struct {
			struct {
				struct in6_addr src;     /*   376    16 */
				/* --- cacheline 6 boundary (384 bytes) was 8 bytes ago --- */
				struct in6_addr dst;     /*   392    16 */
			} addr;                          /*   376    32 */
			__be32     label;                /*   408     4 */
			u16        exthdrs;              /*   412     2 */

			/* XXX 2 bytes hole, try to pack */

			union {
				struct {
					struct in6_addr      src; /*   416    16 */
					struct in6_addr      dst; /*   432    16 */
				} ct_orig;               /*   416    32 */
				struct {
					struct in6_addr      target; /*   416    16 */
					u8     sll[6];   /*   432     6 */
					u8     tll[6];   /*   438     6 */
				} nd;                    /*   416    28 */
			};                               /*   416    32 */
		} ipv6;                                  /*   376    72 */
		struct {
			u32        num_labels_mask;      /*   376     4 */
			__be32     lse[3];               /*   380    12 */
		} mpls;                                  /*   376    16 */
		struct ovs_key_nsh nsh;                  /*   376    24 */
	};                                               /*   376    72 */
	/* --- cacheline 7 boundary (448 bytes) --- */
	struct {
		struct {
			__be16     src;                  /*   448     2 */
			__be16     dst;                  /*   450     2 */
		} orig_tp;                               /*   448     4 */
		u32                mark;                 /*   452     4 */
		struct ovs_key_ct_labels labels;         /*   456    16 */
	} ct;                                            /*   448    24 */

	/* size: 472, cachelines: 8, members: 16 */
	/* paddings: 1, sum paddings: 1 */
	/* last cacheline: 24 bytes */
};

struct sw_flow_key;


struct sw_flow_id {
	u32                        ufid_len;             /*     0     4 */

	/* XXX 4 bytes hole, try to pack */

	union {
		u32                ufid[4];              /*     8    16 */
		struct sw_flow_key * unmasked_key;       /*     8     8 */
	};                                               /*     8    16 */

	/* size: 24, cachelines: 1, members: 2 */
	/* sum members: 20, holes: 1, sum holes: 4 */
	/* last cacheline: 24 bytes */
};

struct cpumask;

struct sw_flow_mask;

struct sw_flow_actions;

struct sw_flow_stats;

struct sw_flow {
	struct callback_head       rcu;
	struct {
		struct hlist_node  node[2];
		u32                hash;
	} flow_table;
	struct {
		struct hlist_node  node[2];
		u32                hash;
	} ufid_table;
	int                        stats_last_writer;
	struct sw_flow_key         key;
	struct sw_flow_id          id;
	struct cpumask *           cpu_used_mask;
	struct sw_flow_mask *      mask;
	struct sw_flow_actions *   sf_acts;
	struct sw_flow_stats *     stats[];
};



struct ethhdr {
	unsigned char              h_dest[6];
	unsigned char              h_source[6];
	__be16                     h_proto;
};

typedef __u16 __sum16;




struct iphdr {
	__u8                       ihl:4;
	__u8                       version:4;
	__u8                       tos;
	__be16                     tot_len;
	__be16                     id;
	__be16                     frag_off;
	__u8                       ttl;
	__u8                       protocol;
	__sum16                    check;
	union {
		struct {
			__be32     saddr;
			__be32     daddr;
		};
		struct {
			__be32     saddr;
			__be32     daddr;
		} addrs;
	};
};






struct ipv6hdr {
	__u8                       priority:4;
	__u8                       version:4;
	__u8                       flow_lbl[3];
	__be16                     payload_len;
	__u8                       nexthdr;
	__u8                       hop_limit;
	union {
		struct {
			struct in6_addr saddr;
			struct in6_addr daddr;
		};
		struct {
			struct in6_addr saddr;
			struct in6_addr daddr;
		} addrs;
	};
};







struct key_tag;

struct user_namespace;

struct ucounts;

typedef unsigned int gfp_t;

struct xarray {
	spinlock_t                 xa_lock;              /*     0     4 */
	gfp_t                      xa_flags;             /*     4     4 */
	void *                     xa_head;              /*     8     8 */

	/* size: 16, cachelines: 1, members: 3 */
	/* last cacheline: 16 bytes */
};

struct idr {
	struct xarray              idr_rt;               /*     0    16 */
	unsigned int               idr_base;             /*    16     4 */
	unsigned int               idr_next;             /*    20     4 */

	/* size: 24, cachelines: 1, members: 3 */
	/* last cacheline: 24 bytes */
};


struct dentry;

struct proc_ns_operations;



struct ns_tree_node {
	struct rb_node             ns_node;              /*     0    24 */
	struct list_head           ns_list_entry;        /*    24    16 */

	/* size: 40, cachelines: 1, members: 2 */
	/* last cacheline: 40 bytes */
};



struct rb_node;

struct rb_root {
	struct rb_node *           rb_node;              /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};


struct ns_tree_root {
	struct rb_root             ns_rb;                /*     0     8 */
	struct list_head           ns_list_head;         /*     8    16 */

	/* size: 24, cachelines: 1, members: 2 */
	/* last cacheline: 24 bytes */
};

struct ns_tree {
	u64                        ns_id;                /*     0     8 */
	atomic_t                   __ns_ref_active;      /*     8     4 */

	/* XXX 4 bytes hole, try to pack */

	struct ns_tree_node        ns_unified_node;      /*    16    40 */
	struct ns_tree_node        ns_tree_node;         /*    56    40 */
	/* --- cacheline 1 boundary (64 bytes) was 32 bytes ago --- */
	struct ns_tree_node        ns_owner_node;        /*    96    40 */
	/* --- cacheline 2 boundary (128 bytes) was 8 bytes ago --- */
	struct ns_tree_root        ns_owner_root;        /*   136    24 */

	/* size: 160, cachelines: 3, members: 6 */
	/* sum members: 156, holes: 1, sum holes: 4 */
	/* last cacheline: 32 bytes */
};



struct ns_common {
	struct {
		refcount_t         __ns_ref;             /*     0     4 */
	} __attribute__((__aligned__(64)));                                               /*     0    64 */

	/* XXX last struct has 60 bytes of padding */

	/* --- cacheline 1 boundary (64 bytes) --- */
	u32                        ns_type;              /*    64     4 */

	/* XXX 4 bytes hole, try to pack */

	struct dentry *            stashed;              /*    72     8 */
	const struct proc_ns_operations  * ops;          /*    80     8 */
	unsigned int               inum;                 /*    88     4 */

	/* XXX 4 bytes hole, try to pack */

	union {
		struct ns_tree     ;                     /*    96   160 */
		struct callback_head ns_rcu;             /*    96    16 */
	};                                               /*    96   160 */

	/* size: 256, cachelines: 4, members: 6 */
	/* sum members: 248, holes: 2, sum holes: 8 */
	/* paddings: 1, sum paddings: 60 */
};

struct ref_tracker_dir {

	/* size: 0, cachelines: 0, members: 0 */
};



struct proc_dir_entry;

struct ctl_table_set;


struct ctl_table;




struct completion;

struct ctl_table_root;

struct ctl_dir;

struct ctl_node;

struct hlist_node;

struct hlist_head {
	struct hlist_node *        first;                /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};

struct ctl_table_header {
	union {
		struct {
			const struct ctl_table  * ctl_table; /*     0     8 */
			int        ctl_table_size;       /*     8     4 */
			int        used;                 /*    12     4 */
			int        count;                /*    16     4 */
			int        nreg;                 /*    20     4 */
		};                                       /*     0    24 */
		struct callback_head rcu;                /*     0    16 */
	};                                               /*     0    24 */
	struct completion *        unregistering;        /*    24     8 */
	const struct ctl_table  *  ctl_table_arg;        /*    32     8 */
	struct ctl_table_root *    root;                 /*    40     8 */
	struct ctl_table_set *     set;                  /*    48     8 */
	struct ctl_dir *           parent;               /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	struct ctl_node *          node;                 /*    64     8 */
	struct hlist_head          inodes;               /*    72     8 */
	enum {
		SYSCTL_TABLE_TYPE_DEFAULT           = 0,
		SYSCTL_TABLE_TYPE_PERMANENTLY_EMPTY = 1,
	} type;                                          /*    80     4 */

	/* size: 88, cachelines: 2, members: 9 */
	/* padding: 4 */
	/* last cacheline: 24 bytes */
};


struct ctl_dir {
	struct ctl_table_header    header;               /*     0    88 */

	/* XXX last struct has 4 bytes of padding */

	/* --- cacheline 1 boundary (64 bytes) was 24 bytes ago --- */
	struct rb_root             root;                 /*    88     8 */

	/* size: 96, cachelines: 2, members: 2 */
	/* paddings: 1, sum paddings: 4 */
	/* last cacheline: 32 bytes */
};

struct ctl_table_set {
	int                        (*is_seen)(struct ctl_table_set *); /*     0     8 */
	struct ctl_dir             dir;                  /*     8    96 */

	/* size: 104, cachelines: 2, members: 2 */
	/* last cacheline: 40 bytes */
};

struct uevent_sock;

struct hlist_head;


struct notifier_block;

struct raw_notifier_head {
	struct notifier_block *    head;                 /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};


struct ctl_table_header;

struct prot_inuse;

struct netns_core {
	struct ctl_table_header *  sysctl_hdr;           /*     0     8 */
	int                        sysctl_somaxconn;     /*     8     4 */
	int                        sysctl_txq_reselection; /*    12     4 */
	int                        sysctl_optmem_max;    /*    16     4 */
	u8                         sysctl_txrehash;      /*    20     1 */
	u8                         sysctl_tstamp_allow_data; /*    21     1 */
	u8                         sysctl_bypass_prot_mem; /*    22     1 */

	/* XXX 1 byte hole, try to pack */

	struct prot_inuse *        prot_inuse;           /*    24     8 */
	struct cpumask *           rps_default_mask;     /*    32     8 */

	/* size: 40, cachelines: 1, members: 9 */
	/* sum members: 39, holes: 1, sum holes: 1 */
	/* last cacheline: 40 bytes */
};

struct ipstats_mib;

struct tcp_mib;

struct linux_mib;

struct udp_mib;

struct linux_xfrm_mib;

struct linux_tls_mib;

struct mptcp_mib;

struct icmp_mib;

struct icmpmsg_mib;

struct icmpv6_mib;

struct icmpv6msg_mib;

struct netns_mib {
	struct ipstats_mib *       ip_statistics;        /*     0     8 */
	struct ipstats_mib *       ipv6_statistics;      /*     8     8 */
	struct tcp_mib *           tcp_statistics;       /*    16     8 */
	struct linux_mib *         net_statistics;       /*    24     8 */
	struct udp_mib *           udp_statistics;       /*    32     8 */
	struct udp_mib *           udp_stats_in6;        /*    40     8 */
	struct linux_xfrm_mib *    xfrm_statistics;      /*    48     8 */
	struct linux_tls_mib *     tls_statistics;       /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	struct mptcp_mib *         mptcp_statistics;     /*    64     8 */
	struct udp_mib *           udplite_statistics;   /*    72     8 */
	struct udp_mib *           udplite_stats_in6;    /*    80     8 */
	struct icmp_mib *          icmp_statistics;      /*    88     8 */
	struct icmpmsg_mib *       icmpmsg_statistics;   /*    96     8 */
	struct icmpv6_mib *        icmpv6_statistics;    /*   104     8 */
	struct icmpv6msg_mib *     icmpv6msg_statistics; /*   112     8 */
	struct proc_dir_entry *    proc_net_devsnmp6;    /*   120     8 */

	/* size: 128, cachelines: 2, members: 16 */
};



struct netns_packet {
	struct mutex               sklist_lock;          /*     0    32 */
	struct hlist_head          sklist;               /*    32     8 */

	/* size: 40, cachelines: 1, members: 2 */
	/* last cacheline: 40 bytes */
};

struct unix_table {
	spinlock_t *               locks;                /*     0     8 */
	struct hlist_head *        buckets;              /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};

struct netns_unix {
	struct unix_table          table;                /*     0    16 */
	int                        sysctl_max_dgram_qlen; /*    16     4 */

	/* XXX 4 bytes hole, try to pack */

	struct ctl_table_header *  ctl;                  /*    24     8 */

	/* size: 32, cachelines: 1, members: 3 */
	/* sum members: 28, holes: 1, sum holes: 4 */
	/* last cacheline: 32 bytes */
};




struct rw_semaphore {
	atomic_long_t              count;                /*     0     8 */
	atomic_long_t              owner;                /*     8     8 */
	struct optimistic_spin_queue osq;                /*    16     4 */
	raw_spinlock_t             wait_lock;            /*    20     4 */
	struct list_head           wait_list;            /*    24    16 */

	/* size: 40, cachelines: 1, members: 5 */
	/* last cacheline: 40 bytes */
};

struct blocking_notifier_head {
	struct rw_semaphore        rwsem;                /*     0    40 */
	struct notifier_block *    head;                 /*    40     8 */

	/* size: 48, cachelines: 1, members: 2 */
	/* last cacheline: 48 bytes */
};

struct netns_nexthop {
	struct rb_root             rb_root;              /*     0     8 */
	struct hlist_head *        devhash;              /*     8     8 */
	unsigned int               seq;                  /*    16     4 */
	u32                        last_id_allocated;    /*    20     4 */
	struct blocking_notifier_head notifier_chain;    /*    24    48 */

	/* size: 72, cachelines: 2, members: 5 */
	/* last cacheline: 8 bytes */
};


struct inet_hashinfo;

struct inet_timewait_death_row {
	refcount_t                 tw_refcount;          /*     0     4 */

	/* XXX 60 bytes hole, try to pack */

	/* --- cacheline 1 boundary (64 bytes) --- */
	struct inet_hashinfo *     hashinfo __attribute__((__aligned__(64))); /*    64     8 */
	int                        sysctl_max_tw_buckets; /*    72     4 */

	/* size: 128, cachelines: 2, members: 3 */
	/* sum members: 16, holes: 1, sum holes: 60 */
	/* padding: 52 */
	/* forced alignments: 1, forced holes: 1, sum forced holes: 60 */
} __attribute__((__aligned__(64)));

struct udp_table;


struct udp_tunnel_gro {
	struct sock *              sk;                   /*     0     8 */
	struct hlist_head          list;                 /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};

struct ipv4_devconf;

struct ip_ra_chain;


struct fib_rules_ops;

struct fib_table;

struct inet_peer_base;

struct fqdir;

struct local_ports {
	u32                        range;                /*     0     4 */
	bool                       warned;               /*     4     1 */

	/* size: 8, cachelines: 1, members: 2 */
	/* padding: 3 */
	/* last cacheline: 8 bytes */
};

struct tcp_congestion_ops;

struct tcp_fastopen_context;

struct seqcount {
	unsigned int               sequence;             /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};
typedef struct seqcount seqcount_t;

struct seqcount_spinlock {
	seqcount_t                 seqcount;             /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};
typedef struct seqcount_spinlock seqcount_spinlock_t;

struct seqlock {
	seqcount_spinlock_t        seqcount;             /*     0     4 */
	spinlock_t                 lock;                 /*     4     4 */

	/* size: 8, cachelines: 1, members: 2 */
	/* last cacheline: 8 bytes */
};
typedef struct seqlock seqlock_t;

typedef unsigned int __kernel_gid32_t;
typedef __kernel_gid32_t gid_t;

typedef struct {
	gid_t                      val;                  /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
} kgid_t;

struct ping_group_range {
	seqlock_t                  lock;                 /*     0     8 */
	kgid_t                     range[2];             /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};


struct sysctl_fib_multipath_hash_seed {
	u32                        user_seed;            /*     0     4 */
	u32                        mp_seed;              /*     4     4 */

	/* size: 8, cachelines: 1, members: 2 */
	/* last cacheline: 8 bytes */
};

struct fib_notifier_ops;

typedef struct {
	u64                        key[2];               /*     0    16 */

	/* size: 16, cachelines: 1, members: 1 */
	/* last cacheline: 16 bytes */
} siphash_key_t;



struct timer_list;


struct timer_list {
	struct hlist_node          entry;                /*     0    16 */
	long unsigned int          expires;              /*    16     8 */
	void                       (*function)(struct timer_list *); /*    24     8 */
	u32                        flags;                /*    32     4 */

	/* size: 40, cachelines: 1, members: 4 */
	/* padding: 4 */
	/* last cacheline: 40 bytes */
};

struct workqueue_struct;

struct delayed_work {
	struct work_struct         work;                 /*     0    32 */
	struct timer_list          timer;                /*    32    40 */

	/* XXX last struct has 4 bytes of padding */

	/* --- cacheline 1 boundary (64 bytes) was 8 bytes ago --- */
	struct workqueue_struct *  wq;                   /*    72     8 */
	int                        cpu;                  /*    80     4 */

	/* size: 88, cachelines: 2, members: 4 */
	/* padding: 4 */
	/* paddings: 1, sum paddings: 4 */
	/* last cacheline: 24 bytes */
};

struct netns_ipv4 {
	__u8                       __cacheline_group_begin__netns_ipv4_read_tx[0]; /*     0     0 */
	u8                         sysctl_tcp_early_retrans; /*     0     1 */
	u8                         sysctl_tcp_tso_win_divisor; /*     1     1 */
	u8                         sysctl_tcp_tso_rtt_log; /*     2     1 */
	u8                         sysctl_tcp_autocorking; /*     3     1 */
	int                        sysctl_tcp_min_snd_mss; /*     4     4 */
	unsigned int               sysctl_tcp_notsent_lowat; /*     8     4 */
	int                        sysctl_tcp_limit_output_bytes; /*    12     4 */
	int                        sysctl_tcp_min_rtt_wlen; /*    16     4 */
	int                        sysctl_tcp_wmem[3];   /*    20    12 */
	u8                         sysctl_ip_fwd_use_pmtu; /*    32     1 */
	__u8                       __cacheline_group_end__netns_ipv4_read_tx[0]; /*    33     0 */
	__u8                       __cacheline_group_begin__netns_ipv4_read_txrx[0]; /*    33     0 */
	__u8                       __cacheline_group_end__netns_ipv4_read_txrx[0]; /*    33     0 */
	__u8                       __cacheline_group_begin__netns_ipv4_read_rx[0]; /*    33     0 */
	u8                         sysctl_tcp_moderate_rcvbuf; /*    33     1 */
	u8                         sysctl_ip_early_demux; /*    34     1 */
	u8                         sysctl_tcp_early_demux; /*    35     1 */
	u8                         sysctl_tcp_l3mdev_accept; /*    36     1 */

	/* XXX 3 bytes hole, try to pack */

	int                        sysctl_tcp_reordering; /*    40     4 */
	int                        sysctl_tcp_rmem[3];   /*    44    12 */
	int                        sysctl_tcp_rcvbuf_low_rtt; /*    56     4 */
	__u8                       __cacheline_group_end__netns_ipv4_read_rx[0]; /*    60     0 */

	/* XXX 4 bytes hole, try to pack */

	/* --- cacheline 1 boundary (64 bytes) --- */
	__u8                       __cacheline_group_begin__icmp[0] __attribute__((__aligned__(64))); /*    64     0 */
	atomic_t                   icmp_global_credit __attribute__((__aligned__(64))); /*    64     4 */
	u32                        icmp_global_stamp;    /*    68     4 */
	__u8                       __cacheline_group_end__icmp[0]; /*    72     0 */

	/* XXX 56 bytes hole, try to pack */

	/* --- cacheline 2 boundary (128 bytes) --- */
	struct {
	} __cacheline_group_pad__icmp __attribute__((__aligned__(64)));              /*   128     0 */
	struct inet_timewait_death_row tcp_death_row __attribute__((__aligned__(64))); /*   128   128 */

	/* XXX last struct has 52 bytes of padding, 1 hole */

	/* --- cacheline 4 boundary (256 bytes) --- */
	struct udp_table *         udp_table;            /*   256     8 */
	struct udp_tunnel_gro      udp_tunnel_gro[2];    /*   264    32 */
	struct ctl_table_header *  forw_hdr;             /*   296     8 */
	struct ctl_table_header *  frags_hdr;            /*   304     8 */
	struct ctl_table_header *  ipv4_hdr;             /*   312     8 */
	/* --- cacheline 5 boundary (320 bytes) --- */
	struct ctl_table_header *  route_hdr;            /*   320     8 */
	struct ctl_table_header *  xfrm4_hdr;            /*   328     8 */
	struct ipv4_devconf *      devconf_all;          /*   336     8 */
	struct ipv4_devconf *      devconf_dflt;         /*   344     8 */
	struct ip_ra_chain *       ra_chain;             /*   352     8 */
	struct mutex               ra_mutex;             /*   360    32 */
	/* --- cacheline 6 boundary (384 bytes) was 8 bytes ago --- */
	struct fib_rules_ops *     rules_ops;            /*   392     8 */
	struct fib_table *         fib_main;             /*   400     8 */
	struct fib_table *         fib_default;          /*   408     8 */
	unsigned int               fib_rules_require_fldissect; /*   416     4 */
	bool                       fib_has_custom_rules; /*   420     1 */
	bool                       fib_has_custom_local_routes; /*   421     1 */
	bool                       fib_offload_disabled; /*   422     1 */
	u8                         sysctl_tcp_shrink_window; /*   423     1 */
	atomic_t                   fib_num_tclassid_users; /*   424     4 */

	/* XXX 4 bytes hole, try to pack */

	struct hlist_head *        fib_table_hash;       /*   432     8 */
	struct sock *              fibnl;                /*   440     8 */
	/* --- cacheline 7 boundary (448 bytes) --- */
	struct hlist_head *        fib_info_hash;        /*   448     8 */
	unsigned int               fib_info_hash_bits;   /*   456     4 */
	unsigned int               fib_info_cnt;         /*   460     4 */
	struct sock *              mc_autojoin_sk;       /*   464     8 */
	struct inet_peer_base *    peers;                /*   472     8 */
	struct fqdir *             fqdir;                /*   480     8 */
	u8                         sysctl_icmp_echo_ignore_all; /*   488     1 */
	u8                         sysctl_icmp_echo_enable_probe; /*   489     1 */
	u8                         sysctl_icmp_echo_ignore_broadcasts; /*   490     1 */
	u8                         sysctl_icmp_ignore_bogus_error_responses; /*   491     1 */
	u8                         sysctl_icmp_errors_use_inbound_ifaddr; /*   492     1 */
	u8                         sysctl_icmp_errors_extension_mask; /*   493     1 */

	/* XXX 2 bytes hole, try to pack */

	int                        sysctl_icmp_ratelimit; /*   496     4 */
	int                        sysctl_icmp_ratemask; /*   500     4 */
	int                        sysctl_icmp_msgs_per_sec; /*   504     4 */
	int                        sysctl_icmp_msgs_burst; /*   508     4 */
	/* --- cacheline 8 boundary (512 bytes) --- */
	u32                        ip_rt_min_pmtu;       /*   512     4 */
	int                        ip_rt_mtu_expires;    /*   516     4 */
	int                        ip_rt_min_advmss;     /*   520     4 */
	struct local_ports         ip_local_ports;       /*   524     8 */

	/* XXX last struct has 3 bytes of padding */

	u8                         sysctl_tcp_ecn;       /*   532     1 */
	u8                         sysctl_tcp_ecn_option; /*   533     1 */
	u8                         sysctl_tcp_ecn_option_beacon; /*   534     1 */
	u8                         sysctl_tcp_ecn_fallback; /*   535     1 */
	u8                         sysctl_ip_default_ttl; /*   536     1 */
	u8                         sysctl_ip_no_pmtu_disc; /*   537     1 */
	u8                         sysctl_ip_fwd_update_priority; /*   538     1 */
	u8                         sysctl_ip_nonlocal_bind; /*   539     1 */
	u8                         sysctl_ip_autobind_reuse; /*   540     1 */
	u8                         sysctl_ip_dynaddr;    /*   541     1 */
	u8                         sysctl_raw_l3mdev_accept; /*   542     1 */
	u8                         sysctl_udp_early_demux; /*   543     1 */
	u8                         sysctl_nexthop_compat_mode; /*   544     1 */
	u8                         sysctl_fwmark_reflect; /*   545     1 */
	u8                         sysctl_tcp_fwmark_accept; /*   546     1 */
	u8                         sysctl_tcp_mtu_probing; /*   547     1 */
	int                        sysctl_tcp_mtu_probe_floor; /*   548     4 */
	int                        sysctl_tcp_base_mss;  /*   552     4 */
	int                        sysctl_tcp_probe_threshold; /*   556     4 */
	u32                        sysctl_tcp_probe_interval; /*   560     4 */
	int                        sysctl_tcp_keepalive_time; /*   564     4 */
	int                        sysctl_tcp_keepalive_intvl; /*   568     4 */
	u8                         sysctl_tcp_keepalive_probes; /*   572     1 */
	u8                         sysctl_tcp_syn_retries; /*   573     1 */
	u8                         sysctl_tcp_synack_retries; /*   574     1 */
	u8                         sysctl_tcp_syncookies; /*   575     1 */
	/* --- cacheline 9 boundary (576 bytes) --- */
	u8                         sysctl_tcp_migrate_req; /*   576     1 */
	u8                         sysctl_tcp_comp_sack_nr; /*   577     1 */
	u8                         sysctl_tcp_backlog_ack_defer; /*   578     1 */
	u8                         sysctl_tcp_pingpong_thresh; /*   579     1 */
	u8                         sysctl_tcp_retries1;  /*   580     1 */
	u8                         sysctl_tcp_retries2;  /*   581     1 */
	u8                         sysctl_tcp_orphan_retries; /*   582     1 */
	u8                         sysctl_tcp_tw_reuse;  /*   583     1 */
	unsigned int               sysctl_tcp_tw_reuse_delay; /*   584     4 */
	int                        sysctl_tcp_fin_timeout; /*   588     4 */
	u8                         sysctl_tcp_sack;      /*   592     1 */
	u8                         sysctl_tcp_window_scaling; /*   593     1 */
	u8                         sysctl_tcp_timestamps; /*   594     1 */

	/* XXX 1 byte hole, try to pack */

	int                        sysctl_tcp_rto_min_us; /*   596     4 */
	int                        sysctl_tcp_rto_max_ms; /*   600     4 */
	u8                         sysctl_tcp_recovery;  /*   604     1 */
	u8                         sysctl_tcp_thin_linear_timeouts; /*   605     1 */
	u8                         sysctl_tcp_slow_start_after_idle; /*   606     1 */
	u8                         sysctl_tcp_retrans_collapse; /*   607     1 */
	u8                         sysctl_tcp_stdurg;    /*   608     1 */
	u8                         sysctl_tcp_rfc1337;   /*   609     1 */
	u8                         sysctl_tcp_abort_on_overflow; /*   610     1 */
	u8                         sysctl_tcp_fack;      /*   611     1 */
	int                        sysctl_tcp_max_reordering; /*   612     4 */
	int                        sysctl_tcp_adv_win_scale; /*   616     4 */
	u8                         sysctl_tcp_dsack;     /*   620     1 */
	u8                         sysctl_tcp_app_win;   /*   621     1 */
	u8                         sysctl_tcp_frto;      /*   622     1 */
	u8                         sysctl_tcp_nometrics_save; /*   623     1 */
	u8                         sysctl_tcp_no_ssthresh_metrics_save; /*   624     1 */
	u8                         sysctl_tcp_workaround_signed_windows; /*   625     1 */

	/* XXX 2 bytes hole, try to pack */

	int                        sysctl_tcp_challenge_ack_limit; /*   628     4 */
	u8                         sysctl_tcp_min_tso_segs; /*   632     1 */
	u8                         sysctl_tcp_reflect_tos; /*   633     1 */

	/* XXX 2 bytes hole, try to pack */

	int                        sysctl_tcp_invalid_ratelimit; /*   636     4 */
	/* --- cacheline 10 boundary (640 bytes) --- */
	int                        sysctl_tcp_pacing_ss_ratio; /*   640     4 */
	int                        sysctl_tcp_pacing_ca_ratio; /*   644     4 */
	unsigned int               sysctl_tcp_child_ehash_entries; /*   648     4 */
	int                        sysctl_tcp_comp_sack_rtt_percent; /*   652     4 */
	long unsigned int          sysctl_tcp_comp_sack_delay_ns; /*   656     8 */
	long unsigned int          sysctl_tcp_comp_sack_slack_ns; /*   664     8 */
	int                        sysctl_max_syn_backlog; /*   672     4 */
	int                        sysctl_tcp_fastopen;  /*   676     4 */
	const struct tcp_congestion_ops  * tcp_congestion_control; /*   680     8 */
	struct tcp_fastopen_context * tcp_fastopen_ctx;  /*   688     8 */
	unsigned int               sysctl_tcp_fastopen_blackhole_timeout; /*   696     4 */
	atomic_t                   tfo_active_disable_times; /*   700     4 */
	/* --- cacheline 11 boundary (704 bytes) --- */
	long unsigned int          tfo_active_disable_stamp; /*   704     8 */
	u32                        tcp_challenge_timestamp; /*   712     4 */
	u32                        tcp_challenge_count;  /*   716     4 */
	u8                         sysctl_tcp_plb_enabled; /*   720     1 */
	u8                         sysctl_tcp_plb_idle_rehash_rounds; /*   721     1 */
	u8                         sysctl_tcp_plb_rehash_rounds; /*   722     1 */
	u8                         sysctl_tcp_plb_suspend_rto_sec; /*   723     1 */
	int                        sysctl_tcp_plb_cong_thresh; /*   724     4 */
	int                        sysctl_udp_wmem_min;  /*   728     4 */
	int                        sysctl_udp_rmem_min;  /*   732     4 */
	u8                         sysctl_fib_notify_on_flag_change; /*   736     1 */
	u8                         sysctl_tcp_syn_linear_timeouts; /*   737     1 */
	u8                         sysctl_udp_l3mdev_accept; /*   738     1 */
	u8                         sysctl_igmp_llm_reports; /*   739     1 */
	int                        sysctl_igmp_max_memberships; /*   740     4 */
	int                        sysctl_igmp_max_msf;  /*   744     4 */
	int                        sysctl_igmp_qrv;      /*   748     4 */
	struct ping_group_range    ping_group_range;     /*   752    16 */
	/* --- cacheline 12 boundary (768 bytes) --- */
	u16                        ping_port_rover;      /*   768     2 */

	/* XXX 2 bytes hole, try to pack */

	atomic_t                   dev_addr_genid;       /*   772     4 */
	unsigned int               sysctl_udp_child_hash_entries; /*   776     4 */

	/* XXX 4 bytes hole, try to pack */

	long unsigned int *        sysctl_local_reserved_ports; /*   784     8 */
	int                        sysctl_ip_prot_sock;  /*   792     4 */

	/* XXX 4 bytes hole, try to pack */

	struct list_head           mr_tables;            /*   800    16 */
	struct fib_rules_ops *     mr_rules_ops;         /*   816     8 */
	struct sysctl_fib_multipath_hash_seed sysctl_fib_multipath_hash_seed; /*   824     8 */
	/* --- cacheline 13 boundary (832 bytes) --- */
	u32                        sysctl_fib_multipath_hash_fields; /*   832     4 */
	u8                         sysctl_fib_multipath_use_neigh; /*   836     1 */
	u8                         sysctl_fib_multipath_hash_policy; /*   837     1 */

	/* XXX 2 bytes hole, try to pack */

	struct fib_notifier_ops *  notifier_ops;         /*   840     8 */
	unsigned int               fib_seq;              /*   848     4 */

	/* XXX 4 bytes hole, try to pack */

	struct fib_notifier_ops *  ipmr_notifier_ops;    /*   856     8 */
	unsigned int               ipmr_seq;             /*   864     4 */
	atomic_t                   rt_genid;             /*   868     4 */
	siphash_key_t              ip_id_key;            /*   872    16 */
	struct hlist_head *        inet_addr_lst;        /*   888     8 */
	/* --- cacheline 14 boundary (896 bytes) --- */
	struct delayed_work        addr_chk_work;        /*   896    88 */

	/* XXX last struct has 4 bytes of padding */

	/* size: 1024, cachelines: 16, members: 181 */
	/* sum members: 894, holes: 13, sum holes: 90 */
	/* padding: 40 */
	/* member types with holes: 1, total: 1 */
	/* paddings: 3, sum paddings: 59 */
	/* forced alignments: 4, forced holes: 2, sum forced holes: 60 */
} __attribute__((__aligned__(64)));

struct dst_ops;


struct dst_entry;


struct neighbour;


struct kmem_cache;


struct percpu_counter {
	raw_spinlock_t             lock;                 /*     0     4 */

	/* XXX 4 bytes hole, try to pack */

	s64                        count;                /*     8     8 */
	struct list_head           list;                 /*    16    16 */
	s32 *                      counters;             /*    32     8 */

	/* size: 40, cachelines: 1, members: 4 */
	/* sum members: 36, holes: 1, sum holes: 4 */
	/* last cacheline: 40 bytes */
};

struct dst_ops {
	short unsigned int         family;               /*     0     2 */

	/* XXX 2 bytes hole, try to pack */

	unsigned int               gc_thresh;            /*     4     4 */
	void                       (*gc)(struct dst_ops *); /*     8     8 */
	struct dst_entry *         (*check)(struct dst_entry *, __u32); /*    16     8 */
	unsigned int               (*default_advmss)(const struct dst_entry  *); /*    24     8 */
	unsigned int               (*mtu)(const struct dst_entry  *); /*    32     8 */
	u32 *                      (*cow_metrics)(struct dst_entry *, long unsigned int); /*    40     8 */
	void                       (*destroy)(struct dst_entry *); /*    48     8 */
	void                       (*ifdown)(struct dst_entry *, struct net_device *); /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	void                       (*negative_advice)(struct sock *, struct dst_entry *); /*    64     8 */
	void                       (*link_failure)(struct sk_buff *); /*    72     8 */
	void                       (*update_pmtu)(struct dst_entry *, struct sock *, struct sk_buff *, u32, bool); /*    80     8 */
	void                       (*redirect)(struct dst_entry *, struct sock *, struct sk_buff *); /*    88     8 */
	int                        (*local_out)(struct net *, struct sock *, struct sk_buff *); /*    96     8 */
	struct neighbour *         (*neigh_lookup)(const struct dst_entry  *, struct sk_buff *, const void  *); /*   104     8 */
	void                       (*confirm_neigh)(const struct dst_entry  *, const void  *); /*   112     8 */
	struct kmem_cache *        kmem_cachep;          /*   120     8 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	struct percpu_counter      pcpuc_entries;        /*   128    40 */

	/* XXX last struct has 1 hole */

	/* size: 192, cachelines: 3, members: 18 */
	/* sum members: 166, holes: 1, sum holes: 2 */
	/* padding: 24 */
	/* member types with holes: 1, total: 1 */
} __attribute__((__aligned__(64)));

struct netns_sysctl_ipv6 {
	struct ctl_table_header *  hdr;                  /*     0     8 */
	struct ctl_table_header *  route_hdr;            /*     8     8 */
	struct ctl_table_header *  icmp_hdr;             /*    16     8 */
	struct ctl_table_header *  frags_hdr;            /*    24     8 */
	struct ctl_table_header *  xfrm6_hdr;            /*    32     8 */
	int                        flush_delay;          /*    40     4 */
	int                        ip6_rt_max_size;      /*    44     4 */
	int                        ip6_rt_gc_min_interval; /*    48     4 */
	int                        ip6_rt_gc_timeout;    /*    52     4 */
	int                        ip6_rt_gc_interval;   /*    56     4 */
	int                        ip6_rt_gc_elasticity; /*    60     4 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	int                        ip6_rt_mtu_expires;   /*    64     4 */
	int                        ip6_rt_min_advmss;    /*    68     4 */
	u32                        multipath_hash_fields; /*    72     4 */
	u8                         multipath_hash_policy; /*    76     1 */
	__u8                       __cacheline_group_begin__sysctl_ipv6_flowlabel[0]; /*    77     0 */
	u8                         flowlabel_consistency; /*    77     1 */
	u8                         auto_flowlabels;      /*    78     1 */
	u8                         flowlabel_state_ranges; /*    79     1 */
	__u8                       __cacheline_group_end__sysctl_ipv6_flowlabel[0]; /*    80     0 */
	u8                         icmpv6_echo_ignore_all; /*    80     1 */
	u8                         icmpv6_echo_ignore_multicast; /*    81     1 */
	u8                         icmpv6_echo_ignore_anycast; /*    82     1 */

	/* XXX 1 byte hole, try to pack */

	int                        icmpv6_time;          /*    84     4 */
	long unsigned int          icmpv6_ratemask[4];   /*    88    32 */
	long unsigned int *        icmpv6_ratemask_ptr;  /*   120     8 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	u8                         anycast_src_echo_reply; /*   128     1 */
	u8                         bindv6only;           /*   129     1 */
	u8                         ip_nonlocal_bind;     /*   130     1 */
	u8                         fwmark_reflect;       /*   131     1 */
	int                        idgen_retries;        /*   132     4 */
	int                        idgen_delay;          /*   136     4 */
	int                        flowlabel_reflect;    /*   140     4 */
	int                        max_dst_opts_cnt;     /*   144     4 */
	int                        max_hbh_opts_cnt;     /*   148     4 */
	int                        max_dst_opts_len;     /*   152     4 */
	int                        max_hbh_opts_len;     /*   156     4 */
	int                        seg6_flowlabel;       /*   160     4 */
	u32                        ioam6_id;             /*   164     4 */
	u64                        ioam6_id_wide;        /*   168     8 */
	u8                         skip_notify_on_dev_down; /*   176     1 */
	u8                         fib_notify_on_flag_change; /*   177     1 */
	u8                         icmpv6_error_anycast_as_unicast; /*   178     1 */
	u8                         icmpv6_errors_extension_mask; /*   179     1 */

	/* size: 184, cachelines: 3, members: 44 */
	/* sum members: 179, holes: 1, sum holes: 1 */
	/* padding: 4 */
	/* last cacheline: 56 bytes */
};

struct ipv6_devconf;

struct fib6_info;

struct rt6_info;

struct rt6_statistics;


struct fib6_table;




struct qrwlock {
	union {
		atomic_t           cnts;                 /*     0     4 */
		struct {
			u8         wlocked;              /*     0     1 */
			u8         __lstate[3];          /*     1     3 */
		};                                       /*     0     4 */
	};                                               /*     0     4 */
	arch_spinlock_t            wait_lock;            /*     4     4 */

	/* size: 8, cachelines: 1, members: 2 */
	/* last cacheline: 8 bytes */
};
typedef struct qrwlock arch_rwlock_t;

struct rwlock {
	arch_rwlock_t              raw_lock;             /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};
typedef struct rwlock rwlock_t;



struct seg6_pernet_data;



struct ioam6_pernet_data;

struct netns_ipv6 {
	struct dst_ops             ip6_dst_ops;          /*     0   192 */

	/* XXX last struct has 24 bytes of padding, 1 hole */

	/* --- cacheline 3 boundary (192 bytes) --- */
	struct netns_sysctl_ipv6   sysctl;               /*   192   184 */

	/* XXX last struct has 4 bytes of padding, 1 hole */

	/* --- cacheline 5 boundary (320 bytes) was 56 bytes ago --- */
	struct ipv6_devconf *      devconf_all;          /*   376     8 */
	/* --- cacheline 6 boundary (384 bytes) --- */
	struct ipv6_devconf *      devconf_dflt;         /*   384     8 */
	struct inet_peer_base *    peers;                /*   392     8 */
	struct fqdir *             fqdir;                /*   400     8 */
	struct fib6_info *         fib6_null_entry;      /*   408     8 */
	struct rt6_info *          ip6_null_entry;       /*   416     8 */
	struct rt6_statistics *    rt6_stats;            /*   424     8 */
	struct timer_list          ip6_fib_timer;        /*   432    40 */

	/* XXX last struct has 4 bytes of padding */

	/* --- cacheline 7 boundary (448 bytes) was 24 bytes ago --- */
	struct hlist_head *        fib_table_hash;       /*   472     8 */
	spinlock_t                 fib_table_hash_lock;  /*   480     4 */

	/* XXX 4 bytes hole, try to pack */

	struct fib6_table *        fib6_main_tbl;        /*   488     8 */
	struct list_head           fib6_walkers;         /*   496    16 */
	/* --- cacheline 8 boundary (512 bytes) --- */
	rwlock_t                   fib6_walker_lock;     /*   512     8 */
	spinlock_t                 fib6_gc_lock;         /*   520     4 */
	atomic_t                   ip6_rt_gc_expire;     /*   524     4 */
	long unsigned int          ip6_rt_last_gc;       /*   528     8 */
	unsigned char              flowlabel_has_excl;   /*   536     1 */
	bool                       fib6_has_custom_rules; /*   537     1 */

	/* XXX 2 bytes hole, try to pack */

	unsigned int               fib6_rules_require_fldissect; /*   540     4 */
	unsigned int               fib6_routes_require_src; /*   544     4 */

	/* XXX 4 bytes hole, try to pack */

	struct rt6_info *          ip6_prohibit_entry;   /*   552     8 */
	struct rt6_info *          ip6_blk_hole_entry;   /*   560     8 */
	struct fib6_table *        fib6_local_tbl;       /*   568     8 */
	/* --- cacheline 9 boundary (576 bytes) --- */
	struct fib_rules_ops *     fib6_rules_ops;       /*   576     8 */
	struct sock *              ndisc_sk;             /*   584     8 */
	struct sock *              tcp_sk;               /*   592     8 */
	struct sock *              igmp_sk;              /*   600     8 */
	struct sock *              mc_autojoin_sk;       /*   608     8 */
	struct hlist_head *        inet6_addr_lst;       /*   616     8 */
	spinlock_t                 addrconf_hash_lock;   /*   624     4 */

	/* XXX 4 bytes hole, try to pack */

	struct delayed_work        addr_chk_work;        /*   632    88 */

	/* XXX last struct has 4 bytes of padding */

	/* --- cacheline 11 boundary (704 bytes) was 16 bytes ago --- */
	struct list_head           mr6_tables;           /*   720    16 */
	struct fib_rules_ops *     mr6_rules_ops;        /*   736     8 */
	atomic_t                   dev_addr_genid;       /*   744     4 */
	atomic_t                   fib6_sernum;          /*   748     4 */
	struct seg6_pernet_data *  seg6_data;            /*   752     8 */
	struct fib_notifier_ops *  notifier_ops;         /*   760     8 */
	/* --- cacheline 12 boundary (768 bytes) --- */
	struct fib_notifier_ops *  ip6mr_notifier_ops;   /*   768     8 */
	unsigned int               ipmr_seq;             /*   776     4 */

	/* XXX 4 bytes hole, try to pack */

	struct {
		struct hlist_head  head;                 /*   784     8 */
		spinlock_t         lock;                 /*   792     4 */
		u32                seq;                  /*   796     4 */
	} ip6addrlbl_table;                              /*   784    16 */
	struct ioam6_pernet_data * ioam6_data;           /*   800     8 */

	/* size: 832, cachelines: 13, members: 43 */
	/* sum members: 790, holes: 5, sum holes: 18 */
	/* padding: 24 */
	/* member types with holes: 2, total: 2 */
	/* paddings: 4, sum paddings: 36 */
} __attribute__((__aligned__(64)));

struct netns_sysctl_lowpan {
	struct ctl_table_header *  frags_hdr;            /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};

struct netns_ieee802154_lowpan {
	struct netns_sysctl_lowpan sysctl;               /*     0     8 */
	struct fqdir *             fqdir;                /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};

struct sctp_mib;





struct netns_sctp {
	struct sctp_mib *          sctp_statistics;      /*     0     8 */
	struct proc_dir_entry *    proc_net_sctp;        /*     8     8 */
	struct ctl_table_header *  sysctl_header;        /*    16     8 */
	struct sock *              ctl_sock;             /*    24     8 */
	struct sock *              udp4_sock;            /*    32     8 */
	struct sock *              udp6_sock;            /*    40     8 */
	int                        udp_port;             /*    48     4 */
	int                        encap_port;           /*    52     4 */
	struct list_head           local_addr_list;      /*    56    16 */
	/* --- cacheline 1 boundary (64 bytes) was 8 bytes ago --- */
	struct list_head           addr_waitq;           /*    72    16 */
	struct timer_list          addr_wq_timer;        /*    88    40 */

	/* XXX last struct has 4 bytes of padding */

	/* --- cacheline 2 boundary (128 bytes) --- */
	struct list_head           auto_asconf_splist;   /*   128    16 */
	spinlock_t                 addr_wq_lock;         /*   144     4 */
	spinlock_t                 local_addr_lock;      /*   148     4 */
	unsigned int               rto_initial;          /*   152     4 */
	unsigned int               rto_min;              /*   156     4 */
	unsigned int               rto_max;              /*   160     4 */
	int                        rto_alpha;            /*   164     4 */
	int                        rto_beta;             /*   168     4 */
	int                        max_burst;            /*   172     4 */
	int                        cookie_preserve_enable; /*   176     4 */
	int                        cookie_auth_enable;   /*   180     4 */
	unsigned int               valid_cookie_life;    /*   184     4 */
	unsigned int               sack_timeout;         /*   188     4 */
	/* --- cacheline 3 boundary (192 bytes) --- */
	unsigned int               hb_interval;          /*   192     4 */
	unsigned int               probe_interval;       /*   196     4 */
	int                        max_retrans_association; /*   200     4 */
	int                        max_retrans_path;     /*   204     4 */
	int                        max_retrans_init;     /*   208     4 */
	int                        pf_retrans;           /*   212     4 */
	int                        ps_retrans;           /*   216     4 */
	int                        pf_enable;            /*   220     4 */
	int                        pf_expose;            /*   224     4 */
	int                        sndbuf_policy;        /*   228     4 */
	int                        rcvbuf_policy;        /*   232     4 */
	int                        default_auto_asconf;  /*   236     4 */
	int                        addip_enable;         /*   240     4 */
	int                        addip_noauth;         /*   244     4 */
	int                        prsctp_enable;        /*   248     4 */
	int                        reconf_enable;        /*   252     4 */
	/* --- cacheline 4 boundary (256 bytes) --- */
	int                        auth_enable;          /*   256     4 */
	int                        intl_enable;          /*   260     4 */
	int                        ecn_enable;           /*   264     4 */
	int                        scope_policy;         /*   268     4 */
	int                        rwnd_upd_shift;       /*   272     4 */

	/* XXX 4 bytes hole, try to pack */

	long unsigned int          max_autoclose;        /*   280     8 */
	int                        l3mdev_accept;        /*   288     4 */

	/* size: 296, cachelines: 5, members: 47 */
	/* sum members: 288, holes: 1, sum holes: 4 */
	/* padding: 4 */
	/* paddings: 1, sum paddings: 4 */
	/* last cacheline: 40 bytes */
};

struct nf_logger;

struct nf_hook_entries;

struct netns_nf {
	struct proc_dir_entry *    proc_netfilter;       /*     0     8 */
	const struct nf_logger  *  nf_loggers[11];       /*     8    88 */
	/* --- cacheline 1 boundary (64 bytes) was 32 bytes ago --- */
	struct ctl_table_header *  nf_log_dir_header;    /*    96     8 */
	struct ctl_table_header *  nf_lwtnl_dir_header;  /*   104     8 */
	struct nf_hook_entries *   hooks_ipv4[5];        /*   112    40 */
	/* --- cacheline 2 boundary (128 bytes) was 24 bytes ago --- */
	struct nf_hook_entries *   hooks_ipv6[5];        /*   152    40 */
	/* --- cacheline 3 boundary (192 bytes) --- */
	struct nf_hook_entries *   hooks_arp[3];         /*   192    24 */
	struct nf_hook_entries *   hooks_bridge[5];      /*   216    40 */
	/* --- cacheline 4 boundary (256 bytes) --- */
	unsigned int               defrag_ipv4_users;    /*   256     4 */
	unsigned int               defrag_ipv6_users;    /*   260     4 */

	/* size: 264, cachelines: 5, members: 10 */
	/* last cacheline: 8 bytes */
};

struct ip_conntrack_stat;

struct nf_ct_event_notifier;

struct nf_generic_net {
	unsigned int               timeout;              /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};

struct nf_tcp_net {
	unsigned int               timeouts[14];         /*     0    56 */
	u8                         tcp_loose;            /*    56     1 */
	u8                         tcp_be_liberal;       /*    57     1 */
	u8                         tcp_max_retrans;      /*    58     1 */
	u8                         tcp_ignore_invalid_rst; /*    59     1 */
	unsigned int               offload_timeout;      /*    60     4 */

	/* size: 64, cachelines: 1, members: 6 */
};

struct nf_udp_net {
	unsigned int               timeouts[2];          /*     0     8 */
	unsigned int               offload_timeout;      /*     8     4 */

	/* size: 12, cachelines: 1, members: 2 */
	/* last cacheline: 12 bytes */
};

struct nf_icmp_net {
	unsigned int               timeout;              /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};


struct nf_sctp_net {
	unsigned int               timeouts[10];         /*     0    40 */

	/* size: 40, cachelines: 1, members: 1 */
	/* last cacheline: 40 bytes */
};


struct nf_gre_net {
	struct list_head           keymap_list;          /*     0    16 */
	unsigned int               timeouts[2];          /*    16     8 */

	/* size: 24, cachelines: 1, members: 2 */
	/* last cacheline: 24 bytes */
};

struct nf_ip_net {
	struct nf_generic_net      generic;              /*     0     4 */
	struct nf_tcp_net          tcp;                  /*     4    64 */
	/* --- cacheline 1 boundary (64 bytes) was 4 bytes ago --- */
	struct nf_udp_net          udp;                  /*    68    12 */
	struct nf_icmp_net         icmp;                 /*    80     4 */
	struct nf_icmp_net         icmpv6;               /*    84     4 */
	struct nf_sctp_net         sctp;                 /*    88    40 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	struct nf_gre_net          gre;                  /*   128    24 */

	/* size: 152, cachelines: 3, members: 7 */
	/* last cacheline: 24 bytes */
};

struct netns_ct {
	bool                       ecache_dwork_pending; /*     0     1 */
	u8                         sysctl_log_invalid;   /*     1     1 */
	u8                         sysctl_events;        /*     2     1 */
	u8                         sysctl_acct;          /*     3     1 */
	u8                         sysctl_tstamp;        /*     4     1 */
	u8                         sysctl_checksum;      /*     5     1 */

	/* XXX 2 bytes hole, try to pack */

	struct ip_conntrack_stat * stat;                 /*     8     8 */
	struct nf_ct_event_notifier * nf_conntrack_event_cb; /*    16     8 */
	struct nf_ip_net           nf_ct_proto;          /*    24   152 */
	/* --- cacheline 2 boundary (128 bytes) was 48 bytes ago --- */
	atomic_t                   labels_used;          /*   176     4 */

	/* size: 184, cachelines: 3, members: 10 */
	/* sum members: 178, holes: 1, sum holes: 2 */
	/* padding: 4 */
	/* last cacheline: 56 bytes */
};

struct netns_nftables {
	unsigned int               base_seq;             /*     0     4 */
	u8                         gencursor;            /*     4     1 */

	/* size: 8, cachelines: 1, members: 2 */
	/* padding: 3 */
	/* last cacheline: 8 bytes */
};

struct nf_flow_table_stat;

struct netns_ft {
	struct nf_flow_table_stat * stat;                /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};

struct net_generic;

struct bpf_prog_array;


struct netns_bpf {
	struct bpf_prog_array *    run_array[2];         /*     0    16 */
	struct bpf_prog *          progs[2];             /*    16    16 */
	struct list_head           links[2];             /*    32    32 */

	/* size: 64, cachelines: 1, members: 3 */
};




struct xfrm_policy_hash {
	struct hlist_head *        table;                /*     0     8 */
	unsigned int               hmask;                /*     8     4 */
	u8                         dbits4;               /*    12     1 */
	u8                         sbits4;               /*    13     1 */
	u8                         dbits6;               /*    14     1 */
	u8                         sbits6;               /*    15     1 */

	/* size: 16, cachelines: 1, members: 6 */
	/* last cacheline: 16 bytes */
};



struct xfrm_policy_hthresh {
	struct work_struct         work;                 /*     0    32 */
	seqlock_t                  lock;                 /*    32     8 */
	u8                         lbits4;               /*    40     1 */
	u8                         rbits4;               /*    41     1 */
	u8                         lbits6;               /*    42     1 */
	u8                         rbits6;               /*    43     1 */

	/* size: 48, cachelines: 1, members: 6 */
	/* padding: 4 */
	/* last cacheline: 48 bytes */
};






struct netns_xfrm {
	struct list_head           state_all;            /*     0    16 */
	struct hlist_head *        state_bydst;          /*    16     8 */
	struct hlist_head *        state_bysrc;          /*    24     8 */
	struct hlist_head *        state_byspi;          /*    32     8 */
	struct hlist_head *        state_byseq;          /*    40     8 */
	struct hlist_head *        state_cache_input;    /*    48     8 */
	unsigned int               state_hmask;          /*    56     4 */
	unsigned int               state_num;            /*    60     4 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	struct work_struct         state_hash_work;      /*    64    32 */
	struct list_head           policy_all;           /*    96    16 */
	struct hlist_head *        policy_byidx;         /*   112     8 */
	unsigned int               policy_idx_hmask;     /*   120     4 */
	unsigned int               idx_generator;        /*   124     4 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	struct xfrm_policy_hash    policy_bydst[3];      /*   128    48 */
	unsigned int               policy_count[6];      /*   176    24 */
	/* --- cacheline 3 boundary (192 bytes) was 8 bytes ago --- */
	struct work_struct         policy_hash_work;     /*   200    32 */
	struct xfrm_policy_hthresh policy_hthresh;       /*   232    48 */

	/* XXX last struct has 4 bytes of padding */

	/* --- cacheline 4 boundary (256 bytes) was 24 bytes ago --- */
	struct list_head           inexact_bins;         /*   280    16 */
	struct sock *              nlsk;                 /*   296     8 */
	struct sock *              nlsk_stash;           /*   304     8 */
	u32                        sysctl_aevent_etime;  /*   312     4 */
	u32                        sysctl_aevent_rseqth; /*   316     4 */
	/* --- cacheline 5 boundary (320 bytes) --- */
	int                        sysctl_larval_drop;   /*   320     4 */
	u32                        sysctl_acq_expires;   /*   324     4 */
	u8                         policy_default[3];    /*   328     3 */

	/* XXX 5 bytes hole, try to pack */

	struct ctl_table_header *  sysctl_hdr;           /*   336     8 */

	/* XXX 40 bytes hole, try to pack */

	/* --- cacheline 6 boundary (384 bytes) --- */
	struct dst_ops             xfrm4_dst_ops __attribute__((__aligned__(64))); /*   384   192 */

	/* XXX last struct has 24 bytes of padding, 1 hole */

	/* --- cacheline 9 boundary (576 bytes) --- */
	struct dst_ops             xfrm6_dst_ops;        /*   576   192 */

	/* XXX last struct has 24 bytes of padding, 1 hole */

	/* --- cacheline 12 boundary (768 bytes) --- */
	spinlock_t                 xfrm_state_lock;      /*   768     4 */
	seqcount_spinlock_t        xfrm_state_hash_generation; /*   772     4 */
	seqcount_spinlock_t        xfrm_policy_hash_generation; /*   776     4 */
	spinlock_t                 xfrm_policy_lock;     /*   780     4 */
	struct mutex               xfrm_cfg_mutex;       /*   784    32 */
	struct delayed_work        nat_keepalive_work;   /*   816    88 */

	/* XXX last struct has 4 bytes of padding */

	/* size: 960, cachelines: 15, members: 34 */
	/* sum members: 859, holes: 2, sum holes: 45 */
	/* padding: 56 */
	/* member types with holes: 2, total: 2 */
	/* paddings: 4, sum paddings: 56 */
	/* forced alignments: 1, forced holes: 1, sum forced holes: 40 */
} __attribute__((__aligned__(64)));

struct netns_ipvs;

struct mpls_route;


struct netns_mpls {
	int                        ip_ttl_propagate;     /*     0     4 */
	int                        default_ttl;          /*     4     4 */
	size_t                     platform_labels;      /*     8     8 */
	struct mpls_route * *      platform_label;       /*    16     8 */
	struct mutex               platform_mutex;       /*    24    32 */
	struct ctl_table_header *  ctl;                  /*    56     8 */

	/* size: 64, cachelines: 1, members: 6 */
};

struct can_dev_rcv_lists;


struct can_pkg_stats;

struct can_rcv_lists_stats;


struct netns_can {
	struct proc_dir_entry *    proc_dir;             /*     0     8 */
	struct proc_dir_entry *    pde_stats;            /*     8     8 */
	struct proc_dir_entry *    pde_reset_stats;      /*    16     8 */
	struct proc_dir_entry *    pde_rcvlist_all;      /*    24     8 */
	struct proc_dir_entry *    pde_rcvlist_fil;      /*    32     8 */
	struct proc_dir_entry *    pde_rcvlist_inv;      /*    40     8 */
	struct proc_dir_entry *    pde_rcvlist_sff;      /*    48     8 */
	struct proc_dir_entry *    pde_rcvlist_eff;      /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	struct proc_dir_entry *    pde_rcvlist_err;      /*    64     8 */
	struct proc_dir_entry *    bcmproc_dir;          /*    72     8 */
	struct can_dev_rcv_lists * rx_alldev_list;       /*    80     8 */
	spinlock_t                 rcvlists_lock;        /*    88     4 */

	/* XXX 4 bytes hole, try to pack */

	struct timer_list          stattimer;            /*    96    40 */

	/* XXX last struct has 4 bytes of padding */

	/* --- cacheline 2 boundary (128 bytes) was 8 bytes ago --- */
	struct can_pkg_stats *     pkg_stats;            /*   136     8 */
	struct can_rcv_lists_stats * rcv_lists_stats;    /*   144     8 */
	struct hlist_head          cgw_list;             /*   152     8 */

	/* size: 160, cachelines: 3, members: 16 */
	/* sum members: 156, holes: 1, sum holes: 4 */
	/* paddings: 1, sum paddings: 4 */
	/* last cacheline: 32 bytes */
};



struct netns_xdp {
	struct mutex               lock;                 /*     0    32 */
	struct hlist_head          list;                 /*    32     8 */

	/* size: 40, cachelines: 1, members: 2 */
	/* last cacheline: 40 bytes */
};







struct netns_mctp {
	struct list_head           routes;               /*     0    16 */
	struct mutex               bind_lock;            /*    16    32 */
	struct hlist_head          binds[128];           /*    48  1024 */
	/* --- cacheline 16 boundary (1024 bytes) was 48 bytes ago --- */
	spinlock_t                 keys_lock;            /*  1072     4 */

	/* XXX 4 bytes hole, try to pack */

	struct hlist_head          keys;                 /*  1080     8 */
	/* --- cacheline 17 boundary (1088 bytes) --- */
	unsigned int               default_net;          /*  1088     4 */

	/* XXX 4 bytes hole, try to pack */

	struct mutex               neigh_lock;           /*  1096    32 */
	struct list_head           neighbours;           /*  1128    16 */

	/* size: 1144, cachelines: 18, members: 8 */
	/* sum members: 1136, holes: 2, sum holes: 8 */
	/* last cacheline: 56 bytes */
};

enum vsock_net_mode {
	VSOCK_NET_MODE_GLOBAL = 0,
	VSOCK_NET_MODE_LOCAL  = 1,
};

struct netns_vsock {
	struct ctl_table_header *  sysctl_hdr;           /*     0     8 */
	u32                        port;                 /*     8     4 */
	enum vsock_net_mode        mode;                 /*    12     4 */
	enum vsock_net_mode        child_ns_mode;        /*    16     4 */

	/* size: 24, cachelines: 1, members: 4 */
	/* padding: 4 */
	/* last cacheline: 24 bytes */
};

struct net {
	refcount_t                 passive;
	spinlock_t                 rules_mod_lock;
	unsigned int               dev_base_seq;
	u32                        ifindex;
	spinlock_t                 nsid_lock;
	atomic_t                   fnhe_genid;
	struct list_head           list;
	struct list_head           exit_list;
	struct llist_node          defer_free_list;
	struct llist_node          cleanup_list;
	struct list_head           ptype_all;
	struct list_head           ptype_specific;
	struct key_tag *           key_domain;
	struct user_namespace *    user_ns;
	struct ucounts *           ucounts;
	struct idr                 netns_ids;
	struct ns_common           ns __attribute__((__aligned__(64)));
	struct ref_tracker_dir     refcnt_tracker;
	struct ref_tracker_dir     notrefcnt_tracker;
	struct list_head           dev_base_head;
	struct proc_dir_entry *    proc_net;
	struct proc_dir_entry *    proc_net_stat;
	struct ctl_table_set       sysctls;
	struct sock *              rtnl;
	struct sock *              genl_sock;
	struct uevent_sock *       uevent_sock;
	struct hlist_head *        dev_name_head;
	struct hlist_head *        dev_index_head;
	struct xarray              dev_by_index;
	struct raw_notifier_head   netdev_chain;
	u32                        hash_mix;
	bool                       is_dying;
	struct net_device *        loopback_dev;
	struct list_head           rules_ops;
	struct netns_core          core;
	struct netns_mib           mib;
	struct netns_packet        packet;
	struct netns_unix          unx;
	struct netns_nexthop       nexthop;
	struct netns_ipv4          ipv4 __attribute__((__aligned__(64)));
	struct netns_ipv6          ipv6;
	struct netns_ieee802154_lowpan ieee802154_lowpan;
	struct netns_sctp          sctp;
	struct netns_nf            nf;
	struct netns_ct            ct;
	struct netns_nftables      nft;
	struct netns_ft            ft;
	struct net_generic *       gen;
	struct netns_bpf           bpf;
	struct netns_xfrm          xfrm __attribute__((__aligned__(64)));
	u64                        net_cookie;
	struct netns_ipvs *        ipvs;
	struct netns_mpls          mpls;
	struct netns_can           can;
	struct netns_xdp           xdp;
	struct netns_mctp          mctp;
	struct sock *              crypto_nlsk;
	struct sock *              diag_nlsk;
	struct netns_vsock         vsock;
} __attribute__((__aligned__(64)));




struct net_device_ops;

struct header_ops;

struct netdev_queue;

typedef u64 netdev_features_t;

struct netdev_tc_txq {
	u16                        count;                /*     0     2 */
	u16                        offset;               /*     2     2 */

	/* size: 4, cachelines: 1, members: 2 */
	/* last cacheline: 4 bytes */
};

struct xps_dev_maps;

struct bpf_mprog_entry;

struct pcpu_lstats;

struct pcpu_sw_netstats;

struct pcpu_dstats;


struct inet6_dev;


struct netdev_rx_queue;

enum rx_handler_result {
	RX_HANDLER_CONSUMED = 0,
	RX_HANDLER_ANOTHER  = 1,
	RX_HANDLER_EXACT    = 2,
	RX_HANDLER_PASS     = 3,
};
typedef enum rx_handler_result rx_handler_result_t;

typedef rx_handler_result_t (rx_handler_func_t)(struct sk_buff * *);

struct netpoll_info;

struct netdev_name_node;

struct dev_ifalias;









typedef u32 xdp_features_t;

struct xdp_metadata_ops;

struct xsk_tx_metadata_ops;
























struct net_device_stats {
	union {
		long unsigned int  rx_packets;           /*     0     8 */
		atomic_long_t      __rx_packets;         /*     0     8 */
	};                                               /*     0     8 */
	union {
		long unsigned int  tx_packets;           /*     8     8 */
		atomic_long_t      __tx_packets;         /*     8     8 */
	};                                               /*     8     8 */
	union {
		long unsigned int  rx_bytes;             /*    16     8 */
		atomic_long_t      __rx_bytes;           /*    16     8 */
	};                                               /*    16     8 */
	union {
		long unsigned int  tx_bytes;             /*    24     8 */
		atomic_long_t      __tx_bytes;           /*    24     8 */
	};                                               /*    24     8 */
	union {
		long unsigned int  rx_errors;            /*    32     8 */
		atomic_long_t      __rx_errors;          /*    32     8 */
	};                                               /*    32     8 */
	union {
		long unsigned int  tx_errors;            /*    40     8 */
		atomic_long_t      __tx_errors;          /*    40     8 */
	};                                               /*    40     8 */
	union {
		long unsigned int  rx_dropped;           /*    48     8 */
		atomic_long_t      __rx_dropped;         /*    48     8 */
	};                                               /*    48     8 */
	union {
		long unsigned int  tx_dropped;           /*    56     8 */
		atomic_long_t      __tx_dropped;         /*    56     8 */
	};                                               /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	union {
		long unsigned int  multicast;            /*    64     8 */
		atomic_long_t      __multicast;          /*    64     8 */
	};                                               /*    64     8 */
	union {
		long unsigned int  collisions;           /*    72     8 */
		atomic_long_t      __collisions;         /*    72     8 */
	};                                               /*    72     8 */
	union {
		long unsigned int  rx_length_errors;     /*    80     8 */
		atomic_long_t      __rx_length_errors;   /*    80     8 */
	};                                               /*    80     8 */
	union {
		long unsigned int  rx_over_errors;       /*    88     8 */
		atomic_long_t      __rx_over_errors;     /*    88     8 */
	};                                               /*    88     8 */
	union {
		long unsigned int  rx_crc_errors;        /*    96     8 */
		atomic_long_t      __rx_crc_errors;      /*    96     8 */
	};                                               /*    96     8 */
	union {
		long unsigned int  rx_frame_errors;      /*   104     8 */
		atomic_long_t      __rx_frame_errors;    /*   104     8 */
	};                                               /*   104     8 */
	union {
		long unsigned int  rx_fifo_errors;       /*   112     8 */
		atomic_long_t      __rx_fifo_errors;     /*   112     8 */
	};                                               /*   112     8 */
	union {
		long unsigned int  rx_missed_errors;     /*   120     8 */
		atomic_long_t      __rx_missed_errors;   /*   120     8 */
	};                                               /*   120     8 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	union {
		long unsigned int  tx_aborted_errors;    /*   128     8 */
		atomic_long_t      __tx_aborted_errors;  /*   128     8 */
	};                                               /*   128     8 */
	union {
		long unsigned int  tx_carrier_errors;    /*   136     8 */
		atomic_long_t      __tx_carrier_errors;  /*   136     8 */
	};                                               /*   136     8 */
	union {
		long unsigned int  tx_fifo_errors;       /*   144     8 */
		atomic_long_t      __tx_fifo_errors;     /*   144     8 */
	};                                               /*   144     8 */
	union {
		long unsigned int  tx_heartbeat_errors;  /*   152     8 */
		atomic_long_t      __tx_heartbeat_errors; /*   152     8 */
	};                                               /*   152     8 */
	union {
		long unsigned int  tx_window_errors;     /*   160     8 */
		atomic_long_t      __tx_window_errors;   /*   160     8 */
	};                                               /*   160     8 */
	union {
		long unsigned int  rx_compressed;        /*   168     8 */
		atomic_long_t      __rx_compressed;      /*   168     8 */
	};                                               /*   168     8 */
	union {
		long unsigned int  tx_compressed;        /*   176     8 */
		atomic_long_t      __tx_compressed;      /*   176     8 */
	};                                               /*   176     8 */

	/* size: 184, cachelines: 3, members: 23 */
	/* last cacheline: 56 bytes */
};

struct net_device_core_stats;

struct ethtool_ops;

struct l3mdev_ops;

struct ndisc_ops;

struct xfrmdev_ops;

struct tlsdev_ops;



struct netdev_hw_addr_list {
	struct list_head           list;                 /*     0    16 */
	int                        count;                /*    16     4 */

	/* XXX 4 bytes hole, try to pack */

	struct rb_root             tree;                 /*    24     8 */

	/* size: 32, cachelines: 1, members: 3 */
	/* sum members: 28, holes: 1, sum holes: 4 */
	/* last cacheline: 32 bytes */
};



struct kset;

struct in_device;


struct vlan_info;

struct dsa_port;

struct tipc_bearer;

struct ax25_dev;

struct wireless_dev;

struct wpan_dev;

struct mpls_dev;

struct mctp_dev;

struct psp_dev;

struct cpu_rmap;


struct Qdisc;

struct xdp_dev_bulk_queue;






enum netdev_ml_priv_type {
	ML_PRIV_NONE = 0,
	ML_PRIV_CAN  = 1,
};

enum netdev_stat_type {
	NETDEV_PCPU_STAT_NONE   = 0,
	NETDEV_PCPU_STAT_LSTATS = 1,
	NETDEV_PCPU_STAT_TSTATS = 2,
	NETDEV_PCPU_STAT_DSTATS = 3,
};

struct garp_port;

struct mrp_port;

struct dm_hw_stat_delta;


struct kobject;

struct kobj_type;

struct kernfs_node;

struct kref {
	refcount_t                 refcount;             /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};

struct kobject {
	const char  *              name;                 /*     0     8 */
	struct list_head           entry;                /*     8    16 */
	struct kobject *           parent;               /*    24     8 */
	struct kset *              kset;                 /*    32     8 */
	const struct kobj_type  *  ktype;                /*    40     8 */
	struct kernfs_node *       sd;                   /*    48     8 */
	struct kref                kref;                 /*    56     4 */
	unsigned int               state_initialized:1;  /*    60: 0  1 */
	unsigned int               state_in_sysfs:1;     /*    60: 1  1 */
	unsigned int               state_add_uevent_sent:1; /*    60: 2  1 */
	unsigned int               state_remove_uevent_sent:1; /*    60: 3  1 */
	unsigned int               uevent_suppress:1;    /*    60: 4  1 */

	/* size: 64, cachelines: 1, members: 12 */
	/* bit_padding: 27 bits */
};

struct device;

struct device_private;

struct device_type;

struct bus_type;

struct device_driver;





enum dl_dev_state {
	DL_DEV_NO_DRIVER    = 0,
	DL_DEV_PROBING      = 1,
	DL_DEV_DRIVER_BOUND = 2,
	DL_DEV_UNBINDING    = 3,
};

struct dev_links_info {
	struct list_head           suppliers;            /*     0    16 */
	struct list_head           consumers;            /*    16    16 */
	struct list_head           defer_sync;           /*    32    16 */
	enum dl_dev_state          status;               /*    48     4 */

	/* size: 56, cachelines: 1, members: 4 */
	/* padding: 4 */
	/* last cacheline: 56 bytes */
};

struct pm_message {
	int                        event;                /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};
typedef struct pm_message pm_message_t;



struct swait_queue_head {
	raw_spinlock_t             lock;                 /*     0     4 */

	/* XXX 4 bytes hole, try to pack */

	struct list_head           task_list;            /*     8    16 */

	/* size: 24, cachelines: 1, members: 2 */
	/* sum members: 20, holes: 1, sum holes: 4 */
	/* last cacheline: 24 bytes */
};

struct completion {
	unsigned int               done;                 /*     0     4 */

	/* XXX 4 bytes hole, try to pack */

	struct swait_queue_head    wait;                 /*     8    24 */

	/* XXX last struct has 1 hole */

	/* size: 32, cachelines: 1, members: 2 */
	/* sum members: 28, holes: 1, sum holes: 4 */
	/* member types with holes: 1, total: 1 */
	/* last cacheline: 32 bytes */
};

struct wakeup_source;


struct timerqueue_node {
	struct rb_node             node;                 /*     0    24 */
	ktime_t                    expires;              /*    24     8 */

	/* size: 32, cachelines: 1, members: 2 */
	/* last cacheline: 32 bytes */
};

enum hrtimer_restart {
	HRTIMER_NORESTART = 0,
	HRTIMER_RESTART   = 1,
};
struct hrtimer;


struct hrtimer_clock_base;

struct hrtimer {
	struct timerqueue_node     node;                 /*     0    32 */
	ktime_t                    _softexpires;         /*    32     8 */
	enum hrtimer_restart       (*function)(struct hrtimer *); /*    40     8 */
	struct hrtimer_clock_base * base;                /*    48     8 */
	u8                         state;                /*    56     1 */
	u8                         is_rel;               /*    57     1 */
	u8                         is_soft;              /*    58     1 */
	u8                         is_hard;              /*    59     1 */

	/* size: 64, cachelines: 1, members: 8 */
	/* padding: 4 */
};



struct wait_queue_head {
	spinlock_t                 lock;                 /*     0     4 */

	/* XXX 4 bytes hole, try to pack */

	struct list_head           head;                 /*     8    16 */

	/* size: 24, cachelines: 1, members: 2 */
	/* sum members: 20, holes: 1, sum holes: 4 */
	/* last cacheline: 24 bytes */
};
typedef struct wait_queue_head wait_queue_head_t;

struct wake_irq;

enum rpm_request {
	RPM_REQ_NONE        = 0,
	RPM_REQ_IDLE        = 1,
	RPM_REQ_SUSPEND     = 2,
	RPM_REQ_AUTOSUSPEND = 3,
	RPM_REQ_RESUME      = 4,
};

enum rpm_status {
	RPM_INVALID    = -1,
	RPM_ACTIVE     = 0,
	RPM_RESUMING   = 1,
	RPM_SUSPENDED  = 2,
	RPM_SUSPENDING = 3,
	RPM_BLOCKED    = 4,
};

struct pm_subsys_data;

struct dev_pm_qos;

struct dev_pm_info {
	pm_message_t               power_state;          /*     0     4 */
	bool                       can_wakeup:1;         /*     4: 0  1 */
	bool                       async_suspend:1;      /*     4: 1  1 */
	bool                       in_dpm_list:1;        /*     4: 2  1 */
	bool                       is_prepared:1;        /*     4: 3  1 */
	bool                       is_suspended:1;       /*     4: 4  1 */
	bool                       is_noirq_suspended:1; /*     4: 5  1 */
	bool                       is_late_suspended:1;  /*     4: 6  1 */
	bool                       no_pm:1;              /*     4: 7  1 */
	bool                       early_init:1;         /*     5: 0  1 */
	bool                       direct_complete:1;    /*     5: 1  1 */

	/* XXX 6 bits hole, try to pack */
	/* XXX 2 bytes hole, try to pack */

	u32                        driver_flags;         /*     8     4 */
	spinlock_t                 lock;                 /*    12     4 */
	struct list_head           entry;                /*    16    16 */
	struct completion          completion;           /*    32    32 */

	/* XXX last struct has 1 hole */

	/* --- cacheline 1 boundary (64 bytes) --- */
	struct wakeup_source *     wakeup;               /*    64     8 */
	bool                       work_in_progress;     /*    72     1 */
	bool                       wakeup_path:1;        /*    73: 0  1 */
	bool                       syscore:1;            /*    73: 1  1 */
	bool                       no_pm_callbacks:1;    /*    73: 2  1 */
	bool                       smart_suspend:1;      /*    73: 3  1 */
	bool                       must_resume:1;        /*    73: 4  1 */
	bool                       may_skip_resume:1;    /*    73: 5  1 */
	bool                       out_band_wakeup:1;    /*    73: 6  1 */
	bool                       strict_midlayer:1;    /*    73: 7  1 */

	/* XXX 6 bytes hole, try to pack */

	struct hrtimer             suspend_timer;        /*    80    64 */

	/* XXX last struct has 4 bytes of padding */

	/* --- cacheline 2 boundary (128 bytes) was 16 bytes ago --- */
	u64                        timer_expires;        /*   144     8 */
	struct work_struct         work;                 /*   152    32 */
	wait_queue_head_t          wait_queue;           /*   184    24 */
	/* --- cacheline 3 boundary (192 bytes) was 16 bytes ago --- */
	struct wake_irq *          wakeirq;              /*   208     8 */
	atomic_t                   usage_count;          /*   216     4 */
	atomic_t                   child_count;          /*   220     4 */
	unsigned int               disable_depth:3;      /*   224: 0  1 */
	bool                       idle_notification:1;  /*   224: 3  1 */
	bool                       request_pending:1;    /*   224: 4  1 */
	bool                       deferred_resume:1;    /*   224: 5  1 */
	bool                       needs_force_resume:1; /*   224: 6  1 */
	bool                       runtime_auto:1;       /*   224: 7  1 */
	bool                       ignore_children:1;    /*   225: 0  1 */
	bool                       no_callbacks:1;       /*   225: 1  1 */
	bool                       irq_safe:1;           /*   225: 2  1 */
	bool                       use_autosuspend:1;    /*   225: 3  1 */
	bool                       timer_autosuspends:1; /*   225: 4  1 */
	bool                       memalloc_noio:1;      /*   225: 5  1 */

	/* XXX 18 bits hole, try to pack */

	unsigned int               links_count;          /*   228     4 */
	enum rpm_request           request;              /*   232     4 */
	enum rpm_status            runtime_status;       /*   236     4 */
	enum rpm_status            last_status;          /*   240     4 */
	int                        runtime_error;        /*   244     4 */
	int                        autosuspend_delay;    /*   248     4 */

	/* XXX 4 bytes hole, try to pack */

	/* --- cacheline 4 boundary (256 bytes) --- */
	u64                        last_busy;            /*   256     8 */
	u64                        active_time;          /*   264     8 */
	u64                        suspended_time;       /*   272     8 */
	u64                        accounting_timestamp; /*   280     8 */
	struct pm_subsys_data *    subsys_data;          /*   288     8 */
	void                       (*set_latency_tolerance)(struct device *, s32); /*   296     8 */
	struct dev_pm_qos *        qos;                  /*   304     8 */
	bool                       detach_power_off:1;   /*   312: 0  1 */

	/* size: 320, cachelines: 5, members: 58 */
	/* sum members: 293, holes: 3, sum holes: 12 */
	/* sum bitfield members: 33 bits, bit holes: 2, sum bit holes: 24 bits */
	/* padding: 7 */
	/* member types with holes: 1, total: 1 */
	/* paddings: 1, sum paddings: 4 */
	/* bit_padding: 7 bits */
};

struct dev_pm_domain;

struct em_perf_domain;

struct dev_pin_info;

struct irq_domain;

struct msi_device_data;

struct dev_msi_info {
	struct irq_domain *        domain;               /*     0     8 */
	struct msi_device_data *   data;                 /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};

struct dma_map_ops;

struct bus_dma_region;

struct device_dma_parameters;


struct cma;

struct io_tlb_mem;

struct dev_archdata {

	/* size: 0, cachelines: 0, members: 0 */
};

struct device_node;

struct fwnode_handle;

typedef u32 __kernel_dev_t;
typedef __kernel_dev_t dev_t;


struct class;

struct attribute_group;

struct iommu_group;

struct dev_iommu;

struct device_physical_location;

enum device_removable {
	DEVICE_REMOVABLE_NOT_SUPPORTED = 0,
	DEVICE_REMOVABLE_UNKNOWN       = 1,
	DEVICE_FIXED                   = 2,
	DEVICE_REMOVABLE               = 3,
};

struct device {
	struct kobject             kobj;                 /*     0    64 */

	/* XXX last struct has 27 bits of padding */

	/* --- cacheline 1 boundary (64 bytes) --- */
	struct device *            parent;               /*    64     8 */
	struct device_private *    p;                    /*    72     8 */
	const char  *              init_name;            /*    80     8 */
	const struct device_type  * type;                /*    88     8 */
	const struct bus_type  *   bus;                  /*    96     8 */
	struct device_driver *     driver;               /*   104     8 */
	void *                     platform_data;        /*   112     8 */
	void *                     driver_data;          /*   120     8 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	struct mutex               mutex;                /*   128    32 */
	struct dev_links_info      links;                /*   160    56 */

	/* XXX last struct has 4 bytes of padding */

	/* --- cacheline 3 boundary (192 bytes) was 24 bytes ago --- */
	struct dev_pm_info         power;                /*   216   320 */

	/* XXX last struct has 7 bytes of padding, 7 bits of padding, 3 holes, 2 bit holes */

	/* --- cacheline 8 boundary (512 bytes) was 24 bytes ago --- */
	struct dev_pm_domain *     pm_domain;            /*   536     8 */
	struct em_perf_domain *    em_pd;                /*   544     8 */
	struct dev_pin_info *      pins;                 /*   552     8 */
	struct dev_msi_info        msi;                  /*   560    16 */
	/* --- cacheline 9 boundary (576 bytes) --- */
	const struct dma_map_ops  * dma_ops;             /*   576     8 */
	u64 *                      dma_mask;             /*   584     8 */
	u64                        coherent_dma_mask;    /*   592     8 */
	u64                        bus_dma_limit;        /*   600     8 */
	const struct bus_dma_region  * dma_range_map;    /*   608     8 */
	struct device_dma_parameters * dma_parms;        /*   616     8 */
	struct list_head           dma_pools;            /*   624    16 */
	/* --- cacheline 10 boundary (640 bytes) --- */
	struct cma *               cma_area;             /*   640     8 */
	struct io_tlb_mem *        dma_io_tlb_mem;       /*   648     8 */
	struct dev_archdata        archdata;             /*   656     0 */
	struct device_node *       of_node;              /*   656     8 */
	struct fwnode_handle *     fwnode;               /*   664     8 */
	int                        numa_node;            /*   672     4 */
	dev_t                      devt;                 /*   676     4 */
	u32                        id;                   /*   680     4 */
	spinlock_t                 devres_lock;          /*   684     4 */
	struct list_head           devres_head;          /*   688    16 */
	/* --- cacheline 11 boundary (704 bytes) --- */
	const struct class  *      class;                /*   704     8 */
	const struct attribute_group  * * groups;        /*   712     8 */
	void                       (*release)(struct device *); /*   720     8 */
	struct iommu_group *       iommu_group;          /*   728     8 */
	struct dev_iommu *         iommu;                /*   736     8 */
	struct device_physical_location * physical_location; /*   744     8 */
	enum device_removable      removable;            /*   752     4 */
	bool                       offline_disabled:1;   /*   756: 0  1 */
	bool                       offline:1;            /*   756: 1  1 */
	bool                       of_node_reused:1;     /*   756: 2  1 */
	bool                       state_synced:1;       /*   756: 3  1 */
	bool                       can_match:1;          /*   756: 4  1 */
	bool                       dma_skip_sync:1;      /*   756: 5  1 */
	bool                       dma_iommu:1;          /*   756: 6  1 */

	/* size: 760, cachelines: 12, members: 47 */
	/* padding: 3 */
	/* member types with holes: 1, total: 3, bit holes: 1, total: 2, bit paddings: 2, total: 34 bits */
	/* paddings: 2, sum paddings: 11 */
	/* bit_padding: 1 bits */
	/* last cacheline: 56 bytes */
};

struct rtnl_link_ops;

struct netdev_stat_ops;

struct netdev_queue_mgmt_ops;

struct dcbnl_rtnl_ops;

struct netprio_map;

struct phy_link_topology;

struct phy_device;

struct sfp_bus;

struct lock_class_key;


struct macsec_ops;

struct udp_tunnel_nic_info;

struct udp_tunnel_nic;

struct netdev_config;

struct ethtool_netdev_state;

struct bpf_xdp_link;

struct bpf_xdp_entity {
	struct bpf_prog *          prog;                 /*     0     8 */
	struct bpf_xdp_link *      link;                 /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};

typedef struct {

	/* size: 0, cachelines: 0, members: 0 */
} netdevice_tracker;

struct rtnl_hw_stats64;

struct devlink_port;

struct dpll_pin;


struct dim_irq_moder;

struct napi_config;


struct net_shaper_hierarchy;


struct hwtstamp_provider;

struct net_device {
	__u8                       __cacheline_group_begin__net_device_read_tx[0];
	union {
		struct {
			long unsigned int priv_flags:32;
			long unsigned int lltx:1;
			long unsigned int netmem_tx:1;
		};
		struct {
			long unsigned int priv_flags:32;
			long unsigned int lltx:1;
			long unsigned int netmem_tx:1;
		} priv_flags_fast;
	};
	const struct net_device_ops  * netdev_ops;
	const struct header_ops  * header_ops;
	struct netdev_queue *      _tx;
	netdev_features_t          gso_partial_features;
	unsigned int               real_num_tx_queues;
	unsigned int               gso_max_size;
	unsigned int               gso_ipv4_max_size;
	u16                        gso_max_segs;
	s16                        num_tc;
	unsigned int               mtu;
	short unsigned int         needed_headroom;
	struct netdev_tc_txq       tc_to_txq[16];
	struct xps_dev_maps *      xps_maps[2];
	struct nf_hook_entries *   nf_hooks_egress;
	struct bpf_mprog_entry *   tcx_egress;
	__u8                       __cacheline_group_end__net_device_read_tx[0];
	__u8                       __cacheline_group_begin__net_device_read_txrx[0];
	union {
		struct pcpu_lstats * lstats;
		struct pcpu_sw_netstats * tstats;
		struct pcpu_dstats * dstats;
	};
	long unsigned int          state;
	unsigned int               flags;
	short unsigned int         hard_header_len;
	netdev_features_t          features;
	struct inet6_dev *         ip6_ptr;
	__u8                       __cacheline_group_end__net_device_read_txrx[0];
	__u8                       __cacheline_group_begin__net_device_read_rx[0];
	struct bpf_prog *          xdp_prog;
	struct list_head           ptype_specific;
	int                        ifindex;
	unsigned int               real_num_rx_queues;
	struct netdev_rx_queue *   _rx;
	unsigned int               gro_max_size;
	unsigned int               gro_ipv4_max_size;
	rx_handler_func_t *        rx_handler;
	void *                     rx_handler_data;
	possible_net_t             nd_net;
	struct netpoll_info *      npinfo;
	struct bpf_mprog_entry *   tcx_ingress;
	__u8                       __cacheline_group_end__net_device_read_rx[0];
	char                       name[16];
	struct netdev_name_node *  name_node;
	struct dev_ifalias *       ifalias;
	long unsigned int          mem_end;
	long unsigned int          mem_start;
	long unsigned int          base_addr;
	struct list_head           dev_list;
	struct list_head           napi_list;
	struct list_head           unreg_list;
	struct list_head           close_list;
	struct list_head           ptype_all;
	struct {
		struct list_head   upper;
		struct list_head   lower;
	} adj_list;
	xdp_features_t             xdp_features;
	const struct xdp_metadata_ops  * xdp_metadata_ops;
	const struct xsk_tx_metadata_ops  * xsk_tx_metadata_ops;
	short unsigned int         gflags;
	short unsigned int         needed_tailroom;
	netdev_features_t          hw_features;
	netdev_features_t          wanted_features;
	netdev_features_t          vlan_features;
	netdev_features_t          hw_enc_features;
	netdev_features_t          mpls_features;
	netdev_features_t          mangleid_features;
	unsigned int               min_mtu;
	unsigned int               max_mtu;
	short unsigned int         type;
	unsigned char              min_header_len;
	unsigned char              name_assign_type;
	int                        group;
	struct net_device_stats    stats;
	struct net_device_core_stats * core_stats;
	atomic_t                   carrier_up_count;
	atomic_t                   carrier_down_count;
	const struct ethtool_ops  * ethtool_ops;
	const struct l3mdev_ops  * l3mdev_ops;
	const struct ndisc_ops  *  ndisc_ops;
	const struct xfrmdev_ops  * xfrmdev_ops;
	const struct tlsdev_ops  * tlsdev_ops;
	unsigned int               operstate;
	unsigned char              link_mode;
	unsigned char              if_port;
	unsigned char              dma;
	unsigned char              perm_addr[32];
	unsigned char              addr_assign_type;
	unsigned char              addr_len;
	unsigned char              upper_level;
	unsigned char              lower_level;
	u8                         threaded;
	short unsigned int         neigh_priv_len;
	short unsigned int         dev_id;
	short unsigned int         dev_port;
	int                        irq;
	u32                        priv_len;
	spinlock_t                 addr_list_lock;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset *              queues_kset;
	unsigned int               promiscuity;
	unsigned int               allmulti;
	bool                       uc_promisc;
	struct in_device *         ip_ptr;
	struct hlist_head          fib_nh_head;
	struct vlan_info *         vlan_info;
	struct dsa_port *          dsa_ptr;
	struct tipc_bearer *       tipc_ptr;
	void *                     atalk_ptr;
	struct ax25_dev *          ax25_ptr;
	struct wireless_dev *      ieee80211_ptr;
	struct wpan_dev *          ieee802154_ptr;
	struct mpls_dev *          mpls_ptr;
	struct mctp_dev *          mctp_ptr;
	struct psp_dev *           psp_dev;
	const unsigned char  *     dev_addr;
	unsigned int               num_rx_queues;
	unsigned int               xdp_zc_max_segs;
	struct netdev_queue *      ingress_queue;
	struct nf_hook_entries *   nf_hooks_ingress;
	unsigned char              broadcast[32];
	struct cpu_rmap *          rx_cpu_rmap;
	struct hlist_node          index_hlist;
	unsigned int               num_tx_queues;
	struct Qdisc *             qdisc;
	unsigned int               tx_queue_len;
	spinlock_t                 tx_global_lock;
	struct xdp_dev_bulk_queue * xdp_bulkq;
	struct hlist_head          qdisc_hash[16];
	struct timer_list          watchdog_timer;
	int                        watchdog_timeo;
	u32                        proto_down_reason;
	struct list_head           todo_list;
	int *                      pcpu_refcnt;
	struct ref_tracker_dir     refcnt_tracker;
	struct list_head           link_watch_list;
	u8                         reg_state;
	bool                       dismantle;
	bool                       moving_ns;
	bool                       rtnl_link_initializing;
	bool                       needs_free_netdev;
	void                       (*priv_destructor)(struct net_device *);
	void *                     ml_priv;
	enum netdev_ml_priv_type   ml_priv_type;
	enum netdev_stat_type      pcpu_stat_type:8;
	struct garp_port *         garp_port;
	struct mrp_port *          mrp_port;
	struct dm_hw_stat_delta *  dm_private;
	struct device              dev;
	const struct attribute_group  * sysfs_groups[5];
	const struct attribute_group  * sysfs_rx_queue_group;
	const struct rtnl_link_ops  * rtnl_link_ops;
	const struct netdev_stat_ops  * stat_ops;
	const struct netdev_queue_mgmt_ops  * queue_mgmt_ops;
	unsigned int               tso_max_size;
	u16                        tso_max_segs;
	const struct dcbnl_rtnl_ops  * dcbnl_ops;
	u8                         prio_tc_map[16];
	unsigned int               fcoe_ddp_xid;
	struct netprio_map *       priomap;
	struct phy_link_topology * link_topo;
	struct phy_device *        phydev;
	struct sfp_bus *           sfp_bus;
	struct lock_class_key *    qdisc_tx_busylock;
	bool                       proto_down;
	bool                       irq_affinity_auto;
	bool                       rx_cpu_rmap_auto;
	long unsigned int          see_all_hwtstamp_requests:1;
	long unsigned int          change_proto_down:1;
	long unsigned int          netns_immutable:1;
	long unsigned int          fcoe_mtu:1;
	struct list_head           net_notifier_list;
	const struct macsec_ops  * macsec_ops;
	const struct udp_tunnel_nic_info  * udp_tunnel_nic_info;
	struct udp_tunnel_nic *    udp_tunnel_nic;
	struct netdev_config *     cfg;
	struct netdev_config *     cfg_pending;
	struct ethtool_netdev_state * ethtool;
	struct bpf_xdp_entity      xdp_state[3];
	u8                         dev_addr_shadow[32];
	netdevice_tracker          linkwatch_dev_tracker;
	netdevice_tracker          watchdog_dev_tracker;
	netdevice_tracker          dev_registered_tracker;
	struct rtnl_hw_stats64 *   offload_xstats_l3;
	struct devlink_port *      devlink_port;
	struct dpll_pin *          dpll_pin;
	struct hlist_head          page_pools;
	struct dim_irq_moder *     irq_moder;
	u64                        max_pacing_offload_horizon;
	struct napi_config *       napi_config;
	u32                        num_napi_configs;
	u32                        napi_defer_hard_irqs;
	long unsigned int          gro_flush_timeout;
	bool                       up;
	bool                       request_ops_lock;
	struct mutex               lock;
	struct net_shaper_hierarchy * net_shaper_hierarchy;
	struct hlist_head          neighbours[2];
	struct hwtstamp_provider * hwprov;
	u8                         priv[] __attribute__((__aligned__(64)));
} __attribute__((__aligned__(64)));

enum skb_drop_reason {
	SKB_NOT_DROPPED_YET                      = 0,
	SKB_CONSUMED                             = 1,
	SKB_DROP_REASON_NOT_SPECIFIED            = 2,
	SKB_DROP_REASON_NO_SOCKET                = 3,
	SKB_DROP_REASON_SOCKET_CLOSE             = 4,
	SKB_DROP_REASON_SOCKET_FILTER            = 5,
	SKB_DROP_REASON_SOCKET_RCVBUFF           = 6,
	SKB_DROP_REASON_UNIX_DISCONNECT          = 7,
	SKB_DROP_REASON_UNIX_SKIP_OOB            = 8,
	SKB_DROP_REASON_PKT_TOO_SMALL            = 9,
	SKB_DROP_REASON_TCP_CSUM                 = 10,
	SKB_DROP_REASON_UDP_CSUM                 = 11,
	SKB_DROP_REASON_NETFILTER_DROP           = 12,
	SKB_DROP_REASON_OTHERHOST                = 13,
	SKB_DROP_REASON_IP_CSUM                  = 14,
	SKB_DROP_REASON_IP_INHDR                 = 15,
	SKB_DROP_REASON_IP_RPFILTER              = 16,
	SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST  = 17,
	SKB_DROP_REASON_XFRM_POLICY              = 18,
	SKB_DROP_REASON_IP_NOPROTO               = 19,
	SKB_DROP_REASON_PROTO_MEM                = 20,
	SKB_DROP_REASON_TCP_AUTH_HDR             = 21,
	SKB_DROP_REASON_TCP_MD5NOTFOUND          = 22,
	SKB_DROP_REASON_TCP_MD5UNEXPECTED        = 23,
	SKB_DROP_REASON_TCP_MD5FAILURE           = 24,
	SKB_DROP_REASON_TCP_AONOTFOUND           = 25,
	SKB_DROP_REASON_TCP_AOUNEXPECTED         = 26,
	SKB_DROP_REASON_TCP_AOKEYNOTFOUND        = 27,
	SKB_DROP_REASON_TCP_AOFAILURE            = 28,
	SKB_DROP_REASON_SOCKET_BACKLOG           = 29,
	SKB_DROP_REASON_TCP_FLAGS                = 30,
	SKB_DROP_REASON_TCP_ABORT_ON_DATA        = 31,
	SKB_DROP_REASON_TCP_ZEROWINDOW           = 32,
	SKB_DROP_REASON_TCP_OLD_DATA             = 33,
	SKB_DROP_REASON_TCP_OVERWINDOW           = 34,
	SKB_DROP_REASON_TCP_OFOMERGE             = 35,
	SKB_DROP_REASON_TCP_RFC7323_PAWS         = 36,
	SKB_DROP_REASON_TCP_RFC7323_PAWS_ACK     = 37,
	SKB_DROP_REASON_TCP_RFC7323_TW_PAWS      = 38,
	SKB_DROP_REASON_TCP_RFC7323_TSECR        = 39,
	SKB_DROP_REASON_TCP_LISTEN_OVERFLOW      = 40,
	SKB_DROP_REASON_TCP_OLD_SEQUENCE         = 41,
	SKB_DROP_REASON_TCP_INVALID_SEQUENCE     = 42,
	SKB_DROP_REASON_TCP_INVALID_END_SEQUENCE = 43,
	SKB_DROP_REASON_TCP_INVALID_ACK_SEQUENCE = 44,
	SKB_DROP_REASON_TCP_RESET                = 45,
	SKB_DROP_REASON_TCP_INVALID_SYN          = 46,
	SKB_DROP_REASON_TCP_CLOSE                = 47,
	SKB_DROP_REASON_TCP_FASTOPEN             = 48,
	SKB_DROP_REASON_TCP_OLD_ACK              = 49,
	SKB_DROP_REASON_TCP_TOO_OLD_ACK          = 50,
	SKB_DROP_REASON_TCP_ACK_UNSENT_DATA      = 51,
	SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE      = 52,
	SKB_DROP_REASON_TCP_OFO_DROP             = 53,
	SKB_DROP_REASON_IP_OUTNOROUTES           = 54,
	SKB_DROP_REASON_BPF_CGROUP_EGRESS        = 55,
	SKB_DROP_REASON_IPV6DISABLED             = 56,
	SKB_DROP_REASON_NEIGH_CREATEFAIL         = 57,
	SKB_DROP_REASON_NEIGH_FAILED             = 58,
	SKB_DROP_REASON_NEIGH_QUEUEFULL          = 59,
	SKB_DROP_REASON_NEIGH_DEAD               = 60,
	SKB_DROP_REASON_NEIGH_HH_FILLFAIL        = 61,
	SKB_DROP_REASON_TC_EGRESS                = 62,
	SKB_DROP_REASON_SECURITY_HOOK            = 63,
	SKB_DROP_REASON_QDISC_DROP               = 64,
	SKB_DROP_REASON_QDISC_BURST_DROP         = 65,
	SKB_DROP_REASON_QDISC_OVERLIMIT          = 66,
	SKB_DROP_REASON_QDISC_CONGESTED          = 67,
	SKB_DROP_REASON_CAKE_FLOOD               = 68,
	SKB_DROP_REASON_FQ_BAND_LIMIT            = 69,
	SKB_DROP_REASON_FQ_HORIZON_LIMIT         = 70,
	SKB_DROP_REASON_FQ_FLOW_LIMIT            = 71,
	SKB_DROP_REASON_CPU_BACKLOG              = 72,
	SKB_DROP_REASON_XDP                      = 73,
	SKB_DROP_REASON_TC_INGRESS               = 74,
	SKB_DROP_REASON_UNHANDLED_PROTO          = 75,
	SKB_DROP_REASON_SKB_CSUM                 = 76,
	SKB_DROP_REASON_SKB_GSO_SEG              = 77,
	SKB_DROP_REASON_SKB_UCOPY_FAULT          = 78,
	SKB_DROP_REASON_DEV_HDR                  = 79,
	SKB_DROP_REASON_DEV_READY                = 80,
	SKB_DROP_REASON_FULL_RING                = 81,
	SKB_DROP_REASON_NOMEM                    = 82,
	SKB_DROP_REASON_HDR_TRUNC                = 83,
	SKB_DROP_REASON_TAP_FILTER               = 84,
	SKB_DROP_REASON_TAP_TXFILTER             = 85,
	SKB_DROP_REASON_ICMP_CSUM                = 86,
	SKB_DROP_REASON_INVALID_PROTO            = 87,
	SKB_DROP_REASON_IP_INADDRERRORS          = 88,
	SKB_DROP_REASON_IP_INNOROUTES            = 89,
	SKB_DROP_REASON_IP_LOCAL_SOURCE          = 90,
	SKB_DROP_REASON_IP_INVALID_SOURCE        = 91,
	SKB_DROP_REASON_IP_LOCALNET              = 92,
	SKB_DROP_REASON_IP_INVALID_DEST          = 93,
	SKB_DROP_REASON_PKT_TOO_BIG              = 94,
	SKB_DROP_REASON_DUP_FRAG                 = 95,
	SKB_DROP_REASON_FRAG_REASM_TIMEOUT       = 96,
	SKB_DROP_REASON_FRAG_TOO_FAR             = 97,
	SKB_DROP_REASON_TCP_MINTTL               = 98,
	SKB_DROP_REASON_IPV6_BAD_EXTHDR          = 99,
	SKB_DROP_REASON_IPV6_NDISC_FRAG          = 100,
	SKB_DROP_REASON_IPV6_NDISC_HOP_LIMIT     = 101,
	SKB_DROP_REASON_IPV6_NDISC_BAD_CODE      = 102,
	SKB_DROP_REASON_IPV6_NDISC_BAD_OPTIONS   = 103,
	SKB_DROP_REASON_IPV6_NDISC_NS_OTHERHOST  = 104,
	SKB_DROP_REASON_QUEUE_PURGE              = 105,
	SKB_DROP_REASON_TC_COOKIE_ERROR          = 106,
	SKB_DROP_REASON_PACKET_SOCK_ERROR        = 107,
	SKB_DROP_REASON_TC_CHAIN_NOTFOUND        = 108,
	SKB_DROP_REASON_TC_RECLASSIFY_LOOP       = 109,
	SKB_DROP_REASON_VXLAN_INVALID_HDR        = 110,
	SKB_DROP_REASON_VXLAN_VNI_NOT_FOUND      = 111,
	SKB_DROP_REASON_MAC_INVALID_SOURCE       = 112,
	SKB_DROP_REASON_VXLAN_ENTRY_EXISTS       = 113,
	SKB_DROP_REASON_NO_TX_TARGET             = 114,
	SKB_DROP_REASON_IP_TUNNEL_ECN            = 115,
	SKB_DROP_REASON_TUNNEL_TXINFO            = 116,
	SKB_DROP_REASON_LOCAL_MAC                = 117,
	SKB_DROP_REASON_ARP_PVLAN_DISABLE        = 118,
	SKB_DROP_REASON_MAC_IEEE_MAC_CONTROL     = 119,
	SKB_DROP_REASON_BRIDGE_INGRESS_STP_STATE = 120,
	SKB_DROP_REASON_CAN_RX_INVALID_FRAME     = 121,
	SKB_DROP_REASON_CANFD_RX_INVALID_FRAME   = 122,
	SKB_DROP_REASON_CANXL_RX_INVALID_FRAME   = 123,
	SKB_DROP_REASON_PFMEMALLOC               = 124,
	SKB_DROP_REASON_DUALPI2_STEP_DROP        = 125,
	SKB_DROP_REASON_PSP_INPUT                = 126,
	SKB_DROP_REASON_PSP_OUTPUT               = 127,
	SKB_DROP_REASON_MAX                      = 128,
	SKB_DROP_REASON_SUBSYS_MASK              = 4294901760,
};


struct skb_shared_hwtstamps {
	union {
		ktime_t            hwtstamp;             /*     0     8 */
		void *             netdev_data;          /*     0     8 */
	};                                               /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};

struct xsk_tx_metadata_compl {
	__u64 *                    tx_timestamp;         /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
};




typedef long unsigned int netmem_ref;

struct skb_frag {
	netmem_ref                 netmem;               /*     0     8 */
	unsigned int               len;                  /*     8     4 */
	unsigned int               offset;               /*    12     4 */

	/* size: 16, cachelines: 1, members: 3 */
	/* last cacheline: 16 bytes */
};
typedef struct skb_frag skb_frag_t;

struct skb_shared_info {
	__u8                       flags;
	__u8                       meta_len;
	__u8                       nr_frags;
	__u8                       tx_flags;
	short unsigned int         gso_size;
	short unsigned int         gso_segs;
	struct sk_buff *           frag_list;
	union {
		struct skb_shared_hwtstamps hwtstamps;
		struct xsk_tx_metadata_compl xsk_meta;
	};
	unsigned int               gso_type;
	u32                        tskey;
	atomic_t                   dataref;
	union {
		struct {
			u32        xdp_frags_size;
			u32        xdp_frags_truesize;
		};
		void *             destructor_arg;
	};
	skb_frag_t                 frags[17];
};

typedef __u64 __addrpair;




typedef __u32 __portpair;






struct proto;



struct inet_timewait_death_row;







struct sock_common {
	union {
		__addrpair         skc_addrpair;         /*     0     8 */
		struct {
			__be32     skc_daddr;            /*     0     4 */
			__be32     skc_rcv_saddr;        /*     4     4 */
		};                                       /*     0     8 */
	};                                               /*     0     8 */
	union {
		unsigned int       skc_hash;             /*     8     4 */
		__u16              skc_u16hashes[2];     /*     8     4 */
	};                                               /*     8     4 */
	union {
		__portpair         skc_portpair;         /*    12     4 */
		struct {
			__be16     skc_dport;            /*    12     2 */
			__u16      skc_num;              /*    14     2 */
		};                                       /*    12     4 */
	};                                               /*    12     4 */
	short unsigned int         skc_family;           /*    16     2 */
	volatile unsigned char     skc_state;            /*    18     1 */
	unsigned char              skc_reuse:4;          /*    19: 0  1 */
	unsigned char              skc_reuseport:1;      /*    19: 4  1 */
	unsigned char              skc_ipv6only:1;       /*    19: 5  1 */
	unsigned char              skc_net_refcnt:1;     /*    19: 6  1 */
	unsigned char              skc_bypass_prot_mem:1; /*    19: 7  1 */
	int                        skc_bound_dev_if;     /*    20     4 */
	union {
		struct hlist_node  skc_bind_node;        /*    24    16 */
		struct hlist_node  skc_portaddr_node;    /*    24    16 */
	};                                               /*    24    16 */
	struct proto *             skc_prot;             /*    40     8 */
	possible_net_t             skc_net;              /*    48     8 */
	struct in6_addr            skc_v6_daddr;         /*    56    16 */
	/* --- cacheline 1 boundary (64 bytes) was 8 bytes ago --- */
	struct in6_addr            skc_v6_rcv_saddr;     /*    72    16 */
	atomic64_t                 skc_cookie;           /*    88     8 */
	union {
		long unsigned int  skc_flags;            /*    96     8 */
		struct sock *      skc_listener;         /*    96     8 */
		struct inet_timewait_death_row * skc_tw_dr; /*    96     8 */
	};                                               /*    96     8 */
	int                        skc_dontcopy_begin[0]; /*   104     0 */
	union {
		struct hlist_node  skc_node;             /*   104    16 */
		struct hlist_nulls_node skc_nulls_node;  /*   104    16 */
	};                                               /*   104    16 */
	short unsigned int         skc_tx_queue_mapping; /*   120     2 */
	short unsigned int         skc_rx_queue_mapping; /*   122     2 */
	union {
		int                skc_incoming_cpu;     /*   124     4 */
		u32                skc_rcv_wnd;          /*   124     4 */
		u32                skc_tw_rcv_nxt;       /*   124     4 */
	};                                               /*   124     4 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	refcount_t                 skc_refcnt;           /*   128     4 */
	int                        skc_dontcopy_end[0];  /*   132     0 */
	union {
		u32                skc_rxhash;           /*   132     4 */
		u32                skc_window_clamp;     /*   132     4 */
		u32                skc_tw_snd_nxt;       /*   132     4 */
	};                                               /*   132     4 */

	/* size: 136, cachelines: 3, members: 26 */
	/* last cacheline: 8 bytes */
};


struct sk_buff_list {
	struct sk_buff *           next;                 /*     0     8 */
	struct sk_buff *           prev;                 /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};


struct sk_buff_head {
	union {
		struct {
			struct sk_buff * next;           /*     0     8 */
			struct sk_buff * prev;           /*     8     8 */
		};                                       /*     0    16 */
		struct sk_buff_list list;                /*     0    16 */
	};                                               /*     0    16 */
	__u32                      qlen;                 /*    16     4 */
	spinlock_t                 lock;                 /*    20     4 */

	/* size: 24, cachelines: 1, members: 3 */
	/* last cacheline: 24 bytes */
};



struct sk_filter;

struct socket_wq;


struct socket;

struct mem_cgroup;

struct xfrm_policy;

struct psp_assoc;

typedef struct {
	spinlock_t                 slock;                /*     0     4 */
	int                        owned;                /*     4     4 */
	wait_queue_head_t          wq;                   /*     8    24 */

	/* size: 32, cachelines: 1, members: 3 */
	/* last cacheline: 32 bytes */
} socket_lock_t;




struct page;

struct page_frag {
	struct page *              page;                 /*     0     8 */
	__u32                      offset;               /*     8     4 */
	__u32                      size;                 /*    12     4 */

	/* size: 16, cachelines: 1, members: 3 */
	/* last cacheline: 16 bytes */
};





typedef unsigned int __kernel_uid32_t;
typedef __kernel_uid32_t uid_t;

typedef struct {
	uid_t                      val;                  /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
} kuid_t;

struct pid;

struct cred;



struct cgroup;

struct sock_cgroup_data {
	struct cgroup *            cgroup;               /*     0     8 */
	u32                        classid;              /*     8     4 */
	u16                        prioidx;              /*    12     2 */

	/* size: 16, cachelines: 1, members: 3 */
	/* padding: 2 */
	/* last cacheline: 16 bytes */
};

struct sock_reuseport;

struct bpf_local_storage;

struct numa_drop_counters;


typedef struct {
	long unsigned int          v;                    /*     0     8 */

	/* size: 8, cachelines: 1, members: 1 */
	/* last cacheline: 8 bytes */
} freeptr_t;


typedef struct {

	/* size: 0, cachelines: 0, members: 0 */
} netns_tracker;


struct sock {
	struct sock_common         __sk_common;
	__u8                       __cacheline_group_begin__sock_write_rx[0];
	atomic_t                   sk_drops;
	__s32                      sk_peek_off;
	struct sk_buff_head        sk_error_queue;
	struct sk_buff_head        sk_receive_queue;
	struct {
		atomic_t           rmem_alloc;
		int                len;
		struct sk_buff *   head;
		struct sk_buff *   tail;
	} sk_backlog;
	__u8                       __cacheline_group_end__sock_write_rx[0];
	__u8                       __cacheline_group_begin__sock_read_rx[0];
	struct dst_entry *         sk_rx_dst;
	int                        sk_rx_dst_ifindex;
	u32                        sk_rx_dst_cookie;
	unsigned int               sk_ll_usec;
	unsigned int               sk_napi_id;
	u16                        sk_busy_poll_budget;
	u8                         sk_prefer_busy_poll;
	u8                         sk_userlocks;
	int                        sk_rcvbuf;
	struct sk_filter *         sk_filter;
	union {
		struct socket_wq * sk_wq;
		struct socket_wq * sk_wq_raw;
	};
	void                       (*sk_data_ready)(struct sock *);
	long int                   sk_rcvtimeo;
	int                        sk_rcvlowat;
	__u8                       __cacheline_group_end__sock_read_rx[0];
	__u8                       __cacheline_group_begin__sock_read_rxtx[0];
	int                        sk_err;
	struct socket *            sk_socket;
	struct mem_cgroup *        sk_memcg;
	struct xfrm_policy *       sk_policy[2];
	struct psp_assoc *         psp_assoc;
	__u8                       __cacheline_group_end__sock_read_rxtx[0];
	__u8                       __cacheline_group_begin__sock_write_rxtx[0];
	socket_lock_t              sk_lock;
	u32                        sk_reserved_mem;
	int                        sk_forward_alloc;
	u32                        sk_tsflags;
	__u8                       __cacheline_group_end__sock_write_rxtx[0];
	__u8                       __cacheline_group_begin__sock_write_tx[0];
	int                        sk_write_pending;
	atomic_t                   sk_omem_alloc;
	int                        sk_err_soft;
	int                        sk_wmem_queued;
	refcount_t                 sk_wmem_alloc;
	long unsigned int          sk_tsq_flags;
	union {
		struct sk_buff *   sk_send_head;
		struct rb_root     tcp_rtx_queue;
	};
	struct sk_buff_head        sk_write_queue;
	struct page_frag           sk_frag;
	union {
		struct timer_list  sk_timer;
		struct timer_list  tcp_retransmit_timer;
		struct timer_list  mptcp_retransmit_timer;
	};
	long unsigned int          sk_pacing_rate;
	atomic_t                   sk_zckey;
	atomic_t                   sk_tskey;
	long unsigned int          sk_tx_queue_mapping_jiffies;
	__u8                       __cacheline_group_end__sock_write_tx[0];
	__u8                       __cacheline_group_begin__sock_read_tx[0];
	u32                        sk_dst_pending_confirm;
	u32                        sk_pacing_status;
	long unsigned int          sk_max_pacing_rate;
	long int                   sk_sndtimeo;
	u32                        sk_priority;
	u32                        sk_mark;
	kuid_t                     sk_uid;
	u16                        sk_protocol;
	u16                        sk_type;
	struct dst_entry *         sk_dst_cache;
	netdev_features_t          sk_route_caps;
	struct sk_buff *           (*sk_validate_xmit_skb)(struct sock *, struct net_device *, struct sk_buff *);
	u16                        sk_gso_type;
	u16                        sk_gso_max_segs;
	unsigned int               sk_gso_max_size;
	gfp_t                      sk_allocation;
	u32                        sk_txhash;
	int                        sk_sndbuf;
	u8                         sk_pacing_shift;
	bool                       sk_use_task_frag;
	__u8                       __cacheline_group_end__sock_read_tx[0];
	u8                         sk_gso_disabled:1;
	u8                         sk_kern_sock:1;
	u8                         sk_no_check_tx:1;
	u8                         sk_no_check_rx:1;
	u8                         sk_shutdown;
	long unsigned int          sk_lingertime;
	struct proto *             sk_prot_creator;
	rwlock_t                   sk_callback_lock;
	u32                        sk_ack_backlog;
	u32                        sk_max_ack_backlog;
	long unsigned int          sk_ino;
	spinlock_t                 sk_peer_lock;
	int                        sk_bind_phc;
	struct pid *               sk_peer_pid;
	const struct cred  *       sk_peer_cred;
	ktime_t                    sk_stamp;
	int                        sk_disconnects;
	union {
		u8                 sk_txrehash;
		u8                 sk_scm_recv_flags;
		struct {
			u8         sk_scm_credentials:1;
			u8         sk_scm_security:1;
			u8         sk_scm_pidfd:1;
			u8         sk_scm_rights:1;
			u8         sk_scm_unused:4;
		};
	};
	u8                         sk_clockid;
	u8                         sk_txtime_deadline_mode:1;
	u8                         sk_txtime_report_errors:1;
	u8                         sk_txtime_unused:6;
	u8                         sk_bpf_cb_flags;
	void *                     sk_user_data;
	void *                     sk_security;
	struct sock_cgroup_data    sk_cgrp_data;
	void                       (*sk_state_change)(struct sock *);
	void                       (*sk_write_space)(struct sock *);
	void                       (*sk_error_report)(struct sock *);
	int                        (*sk_backlog_rcv)(struct sock *, struct sk_buff *);
	void                       (*sk_destruct)(struct sock *);
	struct sock_reuseport *    sk_reuseport_cb;
	struct bpf_local_storage * sk_bpf_storage;
	struct numa_drop_counters * sk_drop_counters;
	union {
		struct callback_head sk_rcu;
		freeptr_t          sk_freeptr;
	};
	netns_tracker              ns_tracker;
	struct xarray              sk_user_frags;
};




struct vlan_ethhdr {
	union {
		struct {
			unsigned char h_dest[6];
			unsigned char h_source[6];
		};
		struct {
			unsigned char h_dest[6];
			unsigned char h_source[6];
		} addrs;
	};
	__be16                     h_vlan_proto;
	__be16                     h_vlan_TCI;
	__be16                     h_vlan_encapsulated_proto;
};



typedef enum {
	SS_FREE          = 0,
	SS_UNCONNECTED   = 1,
	SS_CONNECTING    = 2,
	SS_CONNECTED     = 3,
	SS_DISCONNECTING = 4,
} socket_state;

struct file;

struct proto_ops;

struct fasync_struct;


struct socket_wq {
	wait_queue_head_t          wait;                 /*     0    24 */
	struct fasync_struct *     fasync_list;          /*    24     8 */
	long unsigned int          flags;                /*    32     8 */
	struct callback_head       rcu;                  /*    40    16 */

	/* size: 64, cachelines: 1, members: 4 */
	/* padding: 8 */
} __attribute__((__aligned__(64)));

struct socket {
	socket_state               state;
	short int                  type;
	long unsigned int          flags;
	struct file *              file;
	struct sock *              sk;
	const struct proto_ops  *  ops;
	struct socket_wq           wq __attribute__((__aligned__(64)));
};


typedef short unsigned int umode_t;

struct posix_acl;

struct inode_operations;

struct super_block;

struct address_space;


typedef long long int __kernel_loff_t;
typedef __kernel_loff_t loff_t;

typedef __s64 time64_t;

enum rw_hint {
	WRITE_LIFE_NOT_SET = 0,
	WRITE_LIFE_NONE    = 1,
	WRITE_LIFE_SHORT   = 2,
	WRITE_LIFE_MEDIUM  = 3,
	WRITE_LIFE_LONG    = 4,
	WRITE_LIFE_EXTREME = 5,
	WRITE_LIFE_HINT_NR = 6,
} __attribute__((__packed__));

typedef u64 blkcnt_t;

enum inode_state_flags_enum {
	I_NEW              = 1,
	I_SYNC             = 2,
	I_LRU_ISOLATING    = 4,
	I_DIRTY_SYNC       = 16,
	I_DIRTY_DATASYNC   = 32,
	I_DIRTY_PAGES      = 64,
	I_WILL_FREE        = 128,
	I_FREEING          = 256,
	I_CLEAR            = 512,
	I_REFERENCED       = 1024,
	I_LINKABLE         = 2048,
	I_DIRTY_TIME       = 4096,
	I_WB_SWITCH        = 8192,
	I_OVL_INUSE        = 16384,
	I_CREATING         = 32768,
	I_DONTCACHE        = 65536,
	I_SYNC_QUEUED      = 131072,
	I_PINNING_NETFS_WB = 262144,
};

struct inode_state_flags {
	enum inode_state_flags_enum __state;             /*     0     4 */

	/* size: 4, cachelines: 1, members: 1 */
	/* last cacheline: 4 bytes */
};




struct bdi_writeback;







struct file_operations;

struct inode;



struct file_lock_context;




struct rb_root_cached {
	struct rb_root             rb_root;              /*     0     8 */
	struct rb_node *           rb_leftmost;          /*     8     8 */

	/* size: 16, cachelines: 1, members: 2 */
	/* last cacheline: 16 bytes */
};

struct address_space_operations;

typedef u32 errseq_t;



struct address_space {
	struct inode *             host;                 /*     0     8 */
	struct xarray              i_pages;              /*     8    16 */
	struct rw_semaphore        invalidate_lock;      /*    24    40 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	gfp_t                      gfp_mask;             /*    64     4 */
	atomic_t                   i_mmap_writable;      /*    68     4 */
	atomic_t                   nr_thps;              /*    72     4 */

	/* XXX 4 bytes hole, try to pack */

	struct rb_root_cached      i_mmap;               /*    80    16 */
	long unsigned int          nrpages;              /*    96     8 */
	long unsigned int          writeback_index;      /*   104     8 */
	const struct address_space_operations  * a_ops;  /*   112     8 */
	long unsigned int          flags;                /*   120     8 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	errseq_t                   wb_err;               /*   128     4 */
	spinlock_t                 i_private_lock;       /*   132     4 */
	struct list_head           i_private_list;       /*   136    16 */
	struct rw_semaphore        i_mmap_rwsem;         /*   152    40 */
	/* --- cacheline 3 boundary (192 bytes) --- */
	void *                     i_private_data;       /*   192     8 */

	/* size: 200, cachelines: 4, members: 16 */
	/* sum members: 196, holes: 1, sum holes: 4 */
	/* last cacheline: 8 bytes */
};



struct pipe_inode_info;

struct cdev;


struct fsnotify_mark_connector;

struct inode {
	umode_t                    i_mode;               /*     0     2 */
	short unsigned int         i_opflags;            /*     2     2 */
	unsigned int               i_flags;              /*     4     4 */
	struct posix_acl *         i_acl;                /*     8     8 */
	struct posix_acl *         i_default_acl;        /*    16     8 */
	kuid_t                     i_uid;                /*    24     4 */
	kgid_t                     i_gid;                /*    28     4 */
	const struct inode_operations  * i_op;           /*    32     8 */
	struct super_block *       i_sb;                 /*    40     8 */
	struct address_space *     i_mapping;            /*    48     8 */
	void *                     i_security;           /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	long unsigned int          i_ino;                /*    64     8 */
	union {
		const unsigned int i_nlink;              /*    72     4 */
		unsigned int       __i_nlink;            /*    72     4 */
	};                                               /*    72     4 */
	dev_t                      i_rdev;               /*    76     4 */
	loff_t                     i_size;               /*    80     8 */
	time64_t                   i_atime_sec;          /*    88     8 */
	time64_t                   i_mtime_sec;          /*    96     8 */
	time64_t                   i_ctime_sec;          /*   104     8 */
	u32                        i_atime_nsec;         /*   112     4 */
	u32                        i_mtime_nsec;         /*   116     4 */
	u32                        i_ctime_nsec;         /*   120     4 */
	u32                        i_generation;         /*   124     4 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	spinlock_t                 i_lock;               /*   128     4 */
	short unsigned int         i_bytes;              /*   132     2 */
	u8                         i_blkbits;            /*   134     1 */
	enum rw_hint               i_write_hint;         /*   135     1 */
	blkcnt_t                   i_blocks;             /*   136     8 */
	struct inode_state_flags   i_state;              /*   144     4 */

	/* XXX 4 bytes hole, try to pack */

	struct rw_semaphore        i_rwsem;              /*   152    40 */
	/* --- cacheline 3 boundary (192 bytes) --- */
	long unsigned int          dirtied_when;         /*   192     8 */
	long unsigned int          dirtied_time_when;    /*   200     8 */
	struct hlist_node          i_hash;               /*   208    16 */
	struct list_head           i_io_list;            /*   224    16 */
	struct bdi_writeback *     i_wb;                 /*   240     8 */
	int                        i_wb_frn_winner;      /*   248     4 */
	u16                        i_wb_frn_avg_time;    /*   252     2 */
	u16                        i_wb_frn_history;     /*   254     2 */
	/* --- cacheline 4 boundary (256 bytes) --- */
	struct list_head           i_lru;                /*   256    16 */
	struct list_head           i_sb_list;            /*   272    16 */
	struct list_head           i_wb_list;            /*   288    16 */
	union {
		struct hlist_head  i_dentry;             /*   304     8 */
		struct callback_head i_rcu;              /*   304    16 */
	};                                               /*   304    16 */
	/* --- cacheline 5 boundary (320 bytes) --- */
	atomic64_t                 i_version;            /*   320     8 */
	atomic64_t                 i_sequence;           /*   328     8 */
	atomic_t                   i_count;              /*   336     4 */
	atomic_t                   i_dio_count;          /*   340     4 */
	atomic_t                   i_writecount;         /*   344     4 */
	atomic_t                   i_readcount;          /*   348     4 */
	union {
		const struct file_operations  * i_fop;   /*   352     8 */
		void               (*free_inode)(struct inode *); /*   352     8 */
	};                                               /*   352     8 */
	struct file_lock_context * i_flctx;              /*   360     8 */
	struct address_space       i_data;               /*   368   200 */

	/* XXX last struct has 1 hole */

	/* --- cacheline 8 boundary (512 bytes) was 56 bytes ago --- */
	union {
		struct list_head   i_devices;            /*   568    16 */
		int                i_linklen;            /*   568     4 */
	};                                               /*   568    16 */
	/* --- cacheline 9 boundary (576 bytes) was 8 bytes ago --- */
	union {
		struct pipe_inode_info * i_pipe;         /*   584     8 */
		struct cdev *      i_cdev;               /*   584     8 */
		char *             i_link;               /*   584     8 */
		unsigned int       i_dir_seq;            /*   584     4 */
	};                                               /*   584     8 */
	__u32                      i_fsnotify_mask;      /*   592     4 */

	/* XXX 4 bytes hole, try to pack */

	struct fsnotify_mark_connector * i_fsnotify_marks; /*   600     8 */
	void *                     i_private;            /*   608     8 */

	/* size: 616, cachelines: 10, members: 55 */
	/* sum members: 608, holes: 2, sum holes: 8 */
	/* member types with holes: 1, total: 1 */
	/* last cacheline: 40 bytes */
};

struct socket_alloc {
	struct socket              socket;
	struct inode               vfs_inode;
} __attribute__((__aligned__(64)));

enum sk_rst_reason {
	SK_RST_REASON_NOT_SPECIFIED            = 0,
	SK_RST_REASON_NO_SOCKET                = 1,
	SK_RST_REASON_TCP_INVALID_ACK_SEQUENCE = 2,
	SK_RST_REASON_TCP_RFC7323_PAWS         = 3,
	SK_RST_REASON_TCP_TOO_OLD_ACK          = 4,
	SK_RST_REASON_TCP_ACK_UNSENT_DATA      = 5,
	SK_RST_REASON_TCP_FLAGS                = 6,
	SK_RST_REASON_TCP_OLD_ACK              = 7,
	SK_RST_REASON_TCP_ABORT_ON_DATA        = 8,
	SK_RST_REASON_TCP_TIMEWAIT_SOCKET      = 9,
	SK_RST_REASON_INVALID_SYN              = 10,
	SK_RST_REASON_TCP_ABORT_ON_CLOSE       = 11,
	SK_RST_REASON_TCP_ABORT_ON_LINGER      = 12,
	SK_RST_REASON_TCP_ABORT_ON_MEMORY      = 13,
	SK_RST_REASON_TCP_STATE                = 14,
	SK_RST_REASON_TCP_KEEPALIVE_TIMEOUT    = 15,
	SK_RST_REASON_TCP_DISCONNECT_WITH_DATA = 16,
	SK_RST_REASON_MPTCP_RST_EUNSPEC        = 17,
	SK_RST_REASON_MPTCP_RST_EMPTCP         = 18,
	SK_RST_REASON_MPTCP_RST_ERESOURCE      = 19,
	SK_RST_REASON_MPTCP_RST_EPROHIBIT      = 20,
	SK_RST_REASON_MPTCP_RST_EWQ2BIG        = 21,
	SK_RST_REASON_MPTCP_RST_EBADPERF       = 22,
	SK_RST_REASON_MPTCP_RST_EMIDDLEBOX     = 23,
	SK_RST_REASON_ERROR                    = 24,
	SK_RST_REASON_MAX                      = 25,
};

enum {
	BPF_F_SKIP_FIELD_MASK = 255,
	BPF_F_USER_STACK      = 256,
	BPF_F_FAST_STACK_CMP  = 512,
	BPF_F_REUSE_STACKID   = 1024,
	BPF_F_USER_BUILD_ID   = 2048,
}
;

enum {
	BPF_ANY        = 0,
	BPF_NOEXIST    = 1,
	BPF_EXIST      = 2,
	BPF_F_LOCK     = 4,
	BPF_F_CPU      = 8,
	BPF_F_ALL_CPUS = 16,
}
;

enum {
	BPF_RB_NO_WAKEUP    = 1,
	BPF_RB_FORCE_WAKEUP = 2,
}
;

enum {
	IPPROTO_IP       = 0,
	IPPROTO_ICMP     = 1,
	IPPROTO_IGMP     = 2,
	IPPROTO_IPIP     = 4,
	IPPROTO_TCP      = 6,
	IPPROTO_EGP      = 8,
	IPPROTO_PUP      = 12,
	IPPROTO_UDP      = 17,
	IPPROTO_IDP      = 22,
	IPPROTO_TP       = 29,
	IPPROTO_DCCP     = 33,
	IPPROTO_IPV6     = 41,
	IPPROTO_RSVP     = 46,
	IPPROTO_GRE      = 47,
	IPPROTO_ESP      = 50,
	IPPROTO_AH       = 51,
	IPPROTO_MTP      = 92,
	IPPROTO_BEETPH   = 94,
	IPPROTO_ENCAP    = 98,
	IPPROTO_PIM      = 103,
	IPPROTO_COMP     = 108,
	IPPROTO_L2TP     = 115,
	IPPROTO_SCTP     = 132,
	IPPROTO_UDPLITE  = 136,
	IPPROTO_MPLS     = 137,
	IPPROTO_ETHERNET = 143,
	IPPROTO_AGGFRAG  = 144,
	IPPROTO_RAW      = 255,
	IPPROTO_SMC      = 256,
	IPPROTO_MPTCP    = 262,
	IPPROTO_MAX      = 263,
}
;

enum {
	NFPROTO_UNSPEC   = 0,
	NFPROTO_INET     = 1,
	NFPROTO_IPV4     = 2,
	NFPROTO_ARP      = 3,
	NFPROTO_NETDEV   = 5,
	NFPROTO_BRIDGE   = 7,
	NFPROTO_IPV6     = 10,
	NFPROTO_NUMPROTO = 11,
}
;

#define true 1
#define false 0

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
