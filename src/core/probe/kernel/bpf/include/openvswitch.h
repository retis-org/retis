#ifndef __OPENVSWITCH_H__
#define __OPENVSWITCH_H__

#include "vmlinux.h"

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

enum ovs_key_attr {
	OVS_KEY_ATTR_UNSPEC = 0,
	OVS_KEY_ATTR_ENCAP = 1,
	OVS_KEY_ATTR_PRIORITY = 2,
	OVS_KEY_ATTR_IN_PORT = 3,
	OVS_KEY_ATTR_ETHERNET = 4,
	OVS_KEY_ATTR_VLAN = 5,
	OVS_KEY_ATTR_ETHERTYPE = 6,
	OVS_KEY_ATTR_IPV4 = 7,
	OVS_KEY_ATTR_IPV6 = 8,
	OVS_KEY_ATTR_TCP = 9,
	OVS_KEY_ATTR_UDP = 10,
	OVS_KEY_ATTR_ICMP = 11,
	OVS_KEY_ATTR_ICMPV6 = 12,
	OVS_KEY_ATTR_ARP = 13,
	OVS_KEY_ATTR_ND = 14,
	OVS_KEY_ATTR_SKB_MARK = 15,
	OVS_KEY_ATTR_TUNNEL = 16,
	OVS_KEY_ATTR_SCTP = 17,
	OVS_KEY_ATTR_TCP_FLAGS = 18,
	OVS_KEY_ATTR_DP_HASH = 19,
	OVS_KEY_ATTR_RECIRC_ID = 20,
	OVS_KEY_ATTR_MPLS = 21,
	OVS_KEY_ATTR_CT_STATE = 22,
	OVS_KEY_ATTR_CT_ZONE = 23,
	OVS_KEY_ATTR_CT_MARK = 24,
	OVS_KEY_ATTR_CT_LABELS = 25,
	OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4 = 26,
	OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6 = 27,
	OVS_KEY_ATTR_NSH = 28,
	OVS_KEY_ATTR_PACKET_TYPE = 29,
	OVS_KEY_ATTR_ND_EXTENSIONS = 30,
	OVS_KEY_ATTR_TUNNEL_INFO = 31,
	OVS_KEY_ATTR_IPV6_EXTHDRS = 32,
	__OVS_KEY_ATTR_MAX = 33,
};

struct ovs_key_ct_labels {
	union {
		__u8 ct_labels[16];
		__u32 ct_labels_32[4];
	};
};

struct ovs_nsh_key_base {
	__u8 flags;
	__u8 ttl;
	__u8 mdtype;
	__u8 np;
	__be32 path_hdr;
};

struct vlan_head {
	__be16 tpid;
	__be16 tci;
};

struct ovs_key_nsh {
	struct ovs_nsh_key_base base;
	__be32 context[4];
};

struct sw_flow_key {
	u8 tun_opts[255];
	u8 tun_opts_len;
	struct ip_tunnel_key tun_key;
	struct {
		u32 priority;
		u32 skb_mark;
		u16 in_port;
	} __attribute__((packed)) phy;
	u8 mac_proto;
	u8 tun_proto;
	u32 ovs_flow_hash;
	u32 recirc_id;
	struct {
		u8 src[6];
		u8 dst[6];
		struct vlan_head vlan;
		struct vlan_head cvlan;
		__be16 type;
	} eth;
	u8 ct_state;
	u8 ct_orig_proto;
	union {
		struct {
			u8 proto;
			u8 tos;
			u8 ttl;
			u8 frag;
		} ip;
	};
	u16 ct_zone;
	struct {
		__be16 src;
		__be16 dst;
		__be16 flags;
	} tp;
	union {
		struct {
			struct {
				__be32 src;
				__be32 dst;
			} addr;
			union {
				struct {
					__be32 src;
					__be32 dst;
				} ct_orig;
				struct {
					u8 sha[6];
					u8 tha[6];
				} arp;
			};
		} ipv4;
		struct {
			struct {
				struct in6_addr src;
				struct in6_addr dst;
			} addr;
			__be32 label;
			u16 exthdrs;
			union {
				struct {
					struct in6_addr src;
					struct in6_addr dst;
				} ct_orig;
				struct {
					struct in6_addr target;
					u8 sll[6];
					u8 tll[6];
				} nd;
			};
		} ipv6;
		struct {
			u32 num_labels_mask;
			__be32 lse[3];
		} mpls;
		struct ovs_key_nsh nsh;
	};
	struct {
		struct {
			__be16 src;
			__be16 dst;
		} orig_tp;
		u32 mark;
		struct ovs_key_ct_labels labels;
	} ct;
};

struct sw_flow_key_range {
	short unsigned int start;
	short unsigned int end;
};

struct sw_flow_mask {
	int ref_count;
	struct callback_head rcu;
	struct sw_flow_key_range range;
	struct sw_flow_key key;
};

struct sw_flow_match {
	struct sw_flow_key *key;
	struct sw_flow_key_range range;
	struct sw_flow_mask *mask;
};

struct sw_flow_id {
	u32 ufid_len;
	union {
		u32 ufid[4];
		struct sw_flow_key *unmasked_key;
	};
};

struct sw_flow_actions {
	struct callback_head rcu;
	size_t orig_len;
	u32 actions_len;
	struct nlattr actions[0];
};

struct sw_flow_stats {
	u64 packet_count;
	u64 byte_count;
	long unsigned int used;
	spinlock_t lock;
	__be16 tcp_flags;
};

struct sw_flow {
	struct callback_head rcu;
	struct {
		struct hlist_node node[2];
		u32 hash;
	} flow_table;
	struct {
		struct hlist_node node[2];
		u32 hash;
	} ufid_table;
	int stats_last_writer;
	struct sw_flow_key key;
	struct sw_flow_id id;
	struct cpumask cpu_used_mask;
	struct sw_flow_mask *mask;
	struct sw_flow_actions *sf_acts;
	struct sw_flow_stats *stats[0];
};

struct mask_cache_entry {
	u32 skb_hash;
	u32 mask_index;
};

struct mask_cache {
	struct callback_head rcu;
	u32 cache_size;
	struct mask_cache_entry *mask_cache;
};

struct mask_count {
	int index;
	u64 counter;
};

struct mask_array_stats {
	struct u64_stats_sync syncp;
	u64 usage_cntrs[0];
};

struct mask_array {
	struct callback_head rcu;
	int count;
	int max;
	struct mask_array_stats *masks_usage_stats;
	u64 *masks_usage_zero_cntr;
	struct sw_flow_mask *masks[0];
};

struct table_instance {
	struct hlist_head *buckets;
	unsigned int n_buckets;
	struct callback_head rcu;
	int node_ver;
	u32 hash_seed;
};

struct flow_table {
	struct table_instance *ti;
	struct table_instance *ufid_ti;
	struct mask_cache *mask_cache;
	struct mask_array *mask_array;
	long unsigned int last_rehash;
	unsigned int count;
	unsigned int ufid_count;
};

struct kset___2;

struct kobj_type___2;

struct kernfs_node___2;

struct kobject___2 {
	const char *name;
	struct list_head entry;
	struct kobject___2 *parent;
	struct kset___2 *kset;
	const struct kobj_type___2 *ktype;
	struct kernfs_node___2 *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct module___2;

struct module_kobject___2 {
	struct kobject___2 kobj;
	struct module___2 *mod;
	struct kobject___2 *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct mod_tree_node___2 {
	struct module___2 *mod;
	struct latch_tree_node node;
};

struct module_layout___2 {
	void *base;
	unsigned int size;
	unsigned int text_size;
	unsigned int ro_size;
	unsigned int ro_after_init_size;
	struct mod_tree_node___2 mtn;
};

struct module_attribute___2;

struct kernel_param___2;

struct bpf_raw_event_map___2;

struct module___2 {
	enum module_state state;
	struct list_head list;
	char name[56];
	struct module_kobject___2 mkobj;
	struct module_attribute___2 *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject___2 *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param___2 *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool sig_ok;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	struct module_layout___2 core_layout;
	struct module_layout___2 init_layout;
	struct mod_arch_specific arch;
	long unsigned int taints;
	unsigned int num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map___2 *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	int num_static_call_sites;
	struct static_call_site *static_call_sites;
	int num_kunit_suites;
	struct kunit_suite **kunit_suites;
	bool klp;
	bool klp_alive;
	struct klp_modinfo *klp_info;
	unsigned int printk_index_size;
	struct pi_entry **printk_index_start;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
};

struct dentry___2;

struct super_block___2;

struct file_system_type___2 {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry___2 * (*mount)(struct file_system_type___2 *, int, const char *, void *);
	void (*kill_sb)(struct super_block___2 *);
	struct module___2 *owner;
	struct file_system_type___2 *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

struct kernel_param_ops___2 {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param___2 *);
	int (*get)(char *, const struct kernel_param___2 *);
	void (*free)(void *);
};

struct file___2;

struct kiocb___2;

struct iov_iter___2;

struct poll_table_struct___2;

struct vm_area_struct___2;

struct inode___2;

struct file_lock___2;

struct page___2;

struct pipe_inode_info___2;

struct seq_file___2;

struct file_operations___2 {
	struct module___2 *owner;
	loff_t (*llseek)(struct file___2 *, loff_t, int);
	ssize_t (*read)(struct file___2 *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file___2 *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb___2 *, struct iov_iter___2 *);
	ssize_t (*write_iter)(struct kiocb___2 *, struct iov_iter___2 *);
	int (*iopoll)(struct kiocb___2 *, struct io_comp_batch *, unsigned int);
	int (*iterate)(struct file___2 *, struct dir_context *);
	int (*iterate_shared)(struct file___2 *, struct dir_context *);
	__poll_t (*poll)(struct file___2 *, struct poll_table_struct___2 *);
	long int (*unlocked_ioctl)(struct file___2 *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file___2 *, unsigned int, long unsigned int);
	int (*mmap)(struct file___2 *, struct vm_area_struct___2 *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode___2 *, struct file___2 *);
	int (*flush)(struct file___2 *, fl_owner_t);
	int (*release)(struct inode___2 *, struct file___2 *);
	int (*fsync)(struct file___2 *, loff_t, loff_t, int);
	int (*fasync)(int, struct file___2 *, int);
	int (*lock)(struct file___2 *, int, struct file_lock___2 *);
	ssize_t (*sendpage)(struct file___2 *, struct page___2 *, int, size_t, loff_t *, int);
	long unsigned int (*get_unmapped_area)(struct file___2 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file___2 *, int, struct file_lock___2 *);
	ssize_t (*splice_write)(struct pipe_inode_info___2 *, struct file___2 *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file___2 *, loff_t *, struct pipe_inode_info___2 *, size_t, unsigned int);
	int (*setlease)(struct file___2 *, long int, struct file_lock___2 **, void **);
	long int (*fallocate)(struct file___2 *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file___2 *, struct file___2 *);
	ssize_t (*copy_file_range)(struct file___2 *, loff_t, struct file___2 *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file___2 *, loff_t, struct file___2 *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file___2 *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

struct static_call_mod___2 {
	struct static_call_mod___2 *next;
	struct module___2 *mod;
	struct static_call_site *sites;
};

struct static_call_key___2 {
	void *func;
	union {
		long unsigned int type;
		struct static_call_mod___2 *mods;
		struct static_call_site *sites;
	};
};

typedef struct page___2 *pgtable_t___2;

struct address_space___2;

struct page_pool___2;

struct mm_struct___2;

struct dev_pagemap___2;

struct page___2 {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space___2 *mapping;
			long unsigned int index;
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool___2 *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			union {
				long unsigned int dma_addr_upper;
				atomic_long_t pp_frag_count;
			};
		};
		struct {
			long unsigned int compound_head;
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			atomic_t compound_pincount;
			unsigned int compound_nr;
		};
		struct {
			long unsigned int _compound_pad_1;
			long unsigned int _compound_pad_2;
			struct list_head deferred_list;
		};
		struct {
			long unsigned int _pt_pad_1;
			pgtable_t___2 pmd_huge_pte;
			long unsigned int _pt_pad_2;
			union {
				struct mm_struct___2 *pt_mm;
				atomic_t pt_frag_refcount;
			};
			spinlock_t ptl;
		};
		struct {
			struct dev_pagemap___2 *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	long unsigned int memcg_data;
};

struct page_frag___2 {
	struct page___2 *page;
	__u32 offset;
	__u32 size;
};

struct nsproxy___2;

struct signal_struct___2;

struct bio_list___2;

struct backing_dev_info___2;

struct css_set___2;

struct mem_cgroup___2;

struct vm_struct___2;

struct task_struct___2 {
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct___2 *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	const struct sched_class *sched_class;
	struct rb_node core_node;
	long unsigned int core_cookie;
	unsigned int core_occupation;
	struct task_group *sched_task_group;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_statistics stats;
	struct hlist_head preempt_notifiers;
	unsigned int btrace_seq;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct___2 *mm;
	struct mm_struct___2 *active_mm;
	struct task_rss_stat rss_stat;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	unsigned int sched_psi_wake_requeue: 1;
	int: 28;
	unsigned int sched_remote_wakeup: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int in_user_fault: 1;
	unsigned int in_lru_fault: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_page_owner: 1;
	unsigned int in_eventfd: 1;
	unsigned int pasid_activated: 1;
	unsigned int reported_split_lock: 1;
	unsigned int in_thrashing: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct___2 *real_parent;
	struct task_struct___2 *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct___2 *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_group;
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	struct vtime vtime;
	atomic_t tick_dep_mask;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	struct posix_cputimers_work posix_cputimers_work;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy___2 *nsproxy;
	struct signal_struct___2 *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct audit_context *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct___2 *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	void *journal_info;
	struct bio_list___2 *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct backing_dev_info___2 *backing_dev_info;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	unsigned int psi_flags;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
	struct css_set___2 *cgroups;
	struct list_head cg_list;
	u32 closid;
	u32 rmid;
	struct robust_list_head *robust_list;
	struct compat_robust_list_head *compat_robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	struct perf_event_context *perf_event_ctxp[2];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	long unsigned int preempt_disable_ip;
	struct mempolicy *mempolicy;
	short int il_prev;
	short int pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	long unsigned int numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct numa_group *numa_group;
	long unsigned int *numa_faults;
	long unsigned int total_numa_faults;
	long unsigned int numa_faults_locality[3];
	long unsigned int numa_pages_migrated;
	struct rseq *rseq;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	struct tlbflush_unmap_batch tlb_ubc;
	union {
		refcount_t rcu_users;
		struct callback_head rcu;
	};
	struct pipe_inode_info___2 *splice_pipe;
	struct page_frag___2 task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	int latency_record_count;
	struct latency_record latency_record[32];
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	struct kunit *kunit_test;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace_recursion;
	struct mem_cgroup___2 *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup___2 *active_memcg;
	struct request_queue *throttle_queue;
	struct uprobe_task *utask;
	unsigned int sequential_io;
	unsigned int sequential_io_avg;
	struct kmap_ctrl kmap_ctrl;
	int pagefault_disabled;
	struct task_struct___2 *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct___2 *stack_vm_area;
	refcount_t stack_refcount;
	int patch_state;
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	void *mce_vaddr;
	__u64 mce_kflags;
	u64 mce_addr;
	__u64 mce_ripv: 1;
	__u64 mce_whole_page: 1;
	__u64 __mce_reserved: 62;
	struct callback_head mce_kill_me;
	int mce_count;
	struct llist_head kretprobe_instances;
	struct llist_head rethooks;
	struct callback_head l1d_flush_kill;
	union rv_task_monitor rv[1];
	struct thread_struct thread;
};

struct mm_struct___2 {
	struct {
		struct maple_tree mm_mt;
		long unsigned int (*get_unmapped_area)(struct file___2 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int mmap_compat_base;
		long unsigned int mmap_compat_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		atomic_t mm_count;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[48];
		struct mm_rss_stat rss_stat;
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct___2 *owner;
		struct user_namespace *user_ns;
		struct file___2 *exe_file;
		struct mmu_notifier_subscriptions *notifier_subscriptions;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		atomic_t tlb_flush_batched;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		u32 pasid;
		long unsigned int ksm_merging_pages;
		long unsigned int ksm_rmap_items;
		struct {
			struct list_head list;
			long unsigned int bitmap;
			struct mem_cgroup___2 *memcg;
		} lru_gen;
	};
	long unsigned int cpu_bitmap[0];
};

struct vm_operations_struct___2;

struct vm_area_struct___2 {
	long unsigned int vm_start;
	long unsigned int vm_end;
	struct mm_struct___2 *vm_mm;
	pgprot_t vm_page_prot;
	long unsigned int vm_flags;
	union {
		struct {
			struct rb_node rb;
			long unsigned int rb_subtree_last;
		} shared;
		struct anon_vma_name *anon_name;
	};
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct___2 *vm_ops;
	long unsigned int vm_pgoff;
	struct file___2 *vm_file;
	void *vm_private_data;
	atomic_long_t swap_readahead_info;
	struct mempolicy *vm_policy;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

struct bin_attribute___2;

struct attribute_group___2 {
	const char *name;
	umode_t (*is_visible)(struct kobject___2 *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject___2 *, struct bin_attribute___2 *, int);
	struct attribute **attrs;
	struct bin_attribute___2 **bin_attrs;
};

struct tracepoint___2 {
	const char *name;
	struct static_key key;
	struct static_call_key___2 *static_call_key;
	void *static_call_tramp;
	void *iterator;
	int (*regfunc)();
	void (*unregfunc)();
	struct tracepoint_func *funcs;
};

struct bpf_raw_event_map___2 {
	struct tracepoint___2 *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	long: 64;
};

struct seq_operations___2 {
	void * (*start)(struct seq_file___2 *, loff_t *);
	void (*stop)(struct seq_file___2 *, void *);
	void * (*next)(struct seq_file___2 *, void *, loff_t *);
	int (*show)(struct seq_file___2 *, void *);
};

struct dentry_operations___2;

struct dentry___2 {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry___2 *d_parent;
	struct qstr d_name;
	struct inode___2 *d_inode;
	unsigned char d_iname[32];
	struct lockref d_lockref;
	const struct dentry_operations___2 *d_op;
	struct super_block___2 *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct list_head d_child;
	struct list_head d_subdirs;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

struct address_space_operations___2;

struct address_space___2 {
	struct inode___2 *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	struct rw_semaphore i_mmap_rwsem;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations___2 *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t private_lock;
	struct list_head private_list;
	void *private_data;
};

struct inode_operations___2;

struct bdi_writeback___2;

struct cdev___2;

struct inode___2 {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations___2 *i_op;
	struct super_block___2 *i_sb;
	struct address_space___2 *i_mapping;
	void *i_security;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback___2 *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations___2 *i_fop;
		void (*free_inode)(struct inode___2 *);
	};
	struct file_lock_context *i_flctx;
	struct address_space___2 i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info___2 *i_pipe;
		struct cdev___2 *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_info *i_crypt_info;
	struct fsverity_info *i_verity_info;
	void *i_private;
};

struct vfsmount___2;

struct path___2;

struct dentry_operations___2 {
	int (*d_revalidate)(struct dentry___2 *, unsigned int);
	int (*d_weak_revalidate)(struct dentry___2 *, unsigned int);
	int (*d_hash)(const struct dentry___2 *, struct qstr *);
	int (*d_compare)(const struct dentry___2 *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry___2 *);
	int (*d_init)(struct dentry___2 *);
	void (*d_release)(struct dentry___2 *);
	void (*d_prune)(struct dentry___2 *);
	void (*d_iput)(struct dentry___2 *, struct inode___2 *);
	char * (*d_dname)(struct dentry___2 *, char *, int);
	struct vfsmount___2 * (*d_automount)(struct path___2 *);
	int (*d_manage)(const struct path___2 *, bool);
	struct dentry___2 * (*d_real)(struct dentry___2 *, const struct inode___2 *);
	long: 64;
	long: 64;
	long: 64;
};

struct quota_format_type___2;

struct mem_dqinfo___2 {
	struct quota_format_type___2 *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};

struct quota_format_ops___2;

struct quota_info___2 {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode___2 *files[3];
	struct mem_dqinfo___2 info[3];
	const struct quota_format_ops___2 *ops[3];
};

struct rcuwait___2 {
	struct task_struct___2 *task;
};

struct percpu_rw_semaphore___2 {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait___2 writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers___2 {
	int frozen;
	wait_queue_head_t wait_unfrozen;
	struct percpu_rw_semaphore___2 rw_sem[3];
};

struct shrink_control___2;

struct shrinker___2 {
	long unsigned int (*count_objects)(struct shrinker___2 *, struct shrink_control___2 *);
	long unsigned int (*scan_objects)(struct shrinker___2 *, struct shrink_control___2 *);
	long int batch;
	int seeks;
	unsigned int flags;
	struct list_head list;
	int id;
	atomic_long_t *nr_deferred;
};

struct super_operations___2;

struct dquot_operations___2;

struct quotactl_ops___2;

struct block_device___2;

struct super_block___2 {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type___2 *s_type;
	const struct super_operations___2 *s_op;
	const struct dquot_operations___2 *dq_op;
	const struct quotactl_ops___2 *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry___2 *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	void *s_security;
	const struct xattr_handler **s_xattr;
	const struct fscrypt_operations *s_cop;
	struct fscrypt_keyring *s_master_keys;
	const struct fsverity_operations *s_vop;
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device___2 *s_bdev;
	struct backing_dev_info___2 *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info___2 s_dquot;
	struct sb_writers___2 s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	__u32 s_fsnotify_mask;
	struct fsnotify_mark_connector *s_fsnotify_marks;
	char s_id[32];
	uuid_t s_uuid;
	unsigned int s_max_links;
	fmode_t s_mode;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations___2 *s_d_op;
	struct shrinker___2 s_shrink;
	atomic_long_t s_remove_count;
	atomic_long_t s_fsnotify_connectors;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 64;
	long: 64;
};

struct vfsmount___2 {
	struct dentry___2 *mnt_root;
	struct super_block___2 *mnt_sb;
	int mnt_flags;
	struct user_namespace *mnt_userns;
};

struct path___2 {
	struct vfsmount___2 *mnt;
	struct dentry___2 *dentry;
};

struct shrink_control___2 {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup___2 *memcg;
};

struct mem_cgroup___2 {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct page_counter memory;
	union {
		struct page_counter swap;
		struct page_counter memsw;
	};
	struct page_counter kmem;
	struct page_counter tcpmem;
	struct work_struct high_work;
	long unsigned int zswap_max;
	long unsigned int soft_limit;
	struct vmpressure vmpressure;
	bool oom_group;
	bool oom_lock;
	int under_oom;
	int swappiness;
	int oom_kill_disable;
	struct cgroup_file events_file;
	struct cgroup_file events_local_file;
	struct cgroup_file swap_events_file;
	struct mutex thresholds_lock;
	struct mem_cgroup_thresholds thresholds;
	struct mem_cgroup_thresholds memsw_thresholds;
	struct list_head oom_notify;
	long unsigned int move_charge_at_immigrate;
	spinlock_t move_lock;
	long unsigned int move_lock_flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct memcg_vmstats *vmstats;
	atomic_long_t memory_events[9];
	atomic_long_t memory_events_local[9];
	long unsigned int socket_pressure;
	bool tcpmem_active;
	int tcpmem_pressure;
	int kmemcg_id;
	struct obj_cgroup *objcg;
	struct list_head objcg_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	atomic_t moving_account;
	struct task_struct___2 *move_lock_task;
	struct memcg_vmstats_percpu *vmstats_percpu;
	struct list_head cgwb_list;
	struct wb_domain cgwb_domain;
	struct memcg_cgwb_frn cgwb_frn[4];
	struct list_head event_list;
	spinlock_t event_list_lock;
	struct deferred_split deferred_split_queue;
	struct lru_gen_mm_list mm_list;
	struct mem_cgroup_per_node *nodeinfo[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct device___2;

struct page_pool_params___2 {
	unsigned int flags;
	unsigned int order;
	unsigned int pool_size;
	int nid;
	struct device___2 *dev;
	enum dma_data_direction dma_dir;
	unsigned int max_len;
	unsigned int offset;
	void (*init_callback)(struct page___2 *, void *);
	void *init_arg;
};

struct pp_alloc_cache___2 {
	u32 count;
	struct page___2 *cache[128];
};

struct page_pool___2 {
	struct page_pool_params___2 p;
	struct delayed_work release_dw;
	void (*disconnect)(void *);
	long unsigned int defer_start;
	long unsigned int defer_warn;
	u32 pages_state_hold_cnt;
	unsigned int frag_offset;
	struct page___2 *frag_page;
	long int frag_users;
	u32 xdp_mem_id;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct pp_alloc_cache___2 alloc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct ptr_ring ring;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct dev_pagemap_ops___2;

struct dev_pagemap___2 {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops___2 *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct range ranges[0];
	};
};

struct folio___2 {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space___2 *mapping;
			long unsigned int index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page___2 page;
	};
	long unsigned int _flags_1;
	long unsigned int __head;
	unsigned char _folio_dtor;
	unsigned char _folio_order;
	atomic_t _total_mapcount;
	atomic_t _pincount;
	unsigned int _folio_nr_pages;
};

struct file___2 {
	union {
		struct llist_node f_llist;
		struct callback_head f_rcuhead;
		unsigned int f_iocb_flags;
	};
	struct path___2 f_path;
	struct inode___2 *f_inode;
	const struct file_operations___2 *f_op;
	spinlock_t f_lock;
	atomic_long_t f_count;
	unsigned int f_flags;
	fmode_t f_mode;
	struct mutex f_pos_lock;
	loff_t f_pos;
	struct fown_struct f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	u64 f_version;
	void *f_security;
	void *private_data;
	struct hlist_head *f_ep;
	struct address_space___2 *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};

struct vm_fault___2;

struct vm_operations_struct___2 {
	void (*open)(struct vm_area_struct___2 *);
	void (*close)(struct vm_area_struct___2 *);
	int (*may_split)(struct vm_area_struct___2 *, long unsigned int);
	int (*mremap)(struct vm_area_struct___2 *);
	int (*mprotect)(struct vm_area_struct___2 *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault___2 *);
	vm_fault_t (*huge_fault)(struct vm_fault___2 *, enum page_entry_size);
	vm_fault_t (*map_pages)(struct vm_fault___2 *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct___2 *);
	vm_fault_t (*page_mkwrite)(struct vm_fault___2 *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault___2 *);
	int (*access)(struct vm_area_struct___2 *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct___2 *);
	int (*set_policy)(struct vm_area_struct___2 *, struct mempolicy *);
	struct mempolicy * (*get_policy)(struct vm_area_struct___2 *, long unsigned int);
	struct page___2 * (*find_special_page)(struct vm_area_struct___2 *, long unsigned int);
};

struct vm_fault___2 {
	const struct {
		struct vm_area_struct___2 *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page___2 *cow_page;
	struct page___2 *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t___2 prealloc_pte;
};

struct lruvec___2;

struct lru_gen_mm_walk___2 {
	struct lruvec___2 *lruvec;
	long unsigned int max_seq;
	long unsigned int next_addr;
	int nr_pages[40];
	int mm_stats[6];
	int batched;
	bool can_swap;
	bool force_scan;
};

struct pglist_data___2;

struct lruvec___2 {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
	struct lru_gen_struct lrugen;
	struct lru_gen_mm_state mm_state;
	struct pglist_data___2 *pgdat;
};

struct zone___2 {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long int lowmem_reserve[5];
	int node;
	struct pglist_data___2 *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high;
	int pageset_batch;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	long unsigned int present_early_pages;
	long unsigned int cma_pages;
	const char *name;
	long unsigned int nr_isolate_pageblock;
	seqlock_t span_seqlock;
	int initialized;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct free_area free_area[11];
	long unsigned int flags;
	spinlock_t lock;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int percpu_drift_mark;
	long unsigned int compact_cached_free_pfn;
	long unsigned int compact_cached_migrate_pfn[2];
	long unsigned int compact_init_migrate_pfn;
	long unsigned int compact_init_free_pfn;
	unsigned int compact_considered;
	unsigned int compact_defer_shift;
	int compact_order_failed;
	bool compact_blockskip_flush;
	bool contiguous;
	short: 16;
	struct cacheline_padding _pad3_;
	atomic_long_t vm_stat[11];
	atomic_long_t vm_numa_event[6];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct zoneref___2 {
	struct zone___2 *zone;
	int zone_idx;
};

struct zonelist___2 {
	struct zoneref___2 _zonerefs[5121];
};

struct pglist_data___2 {
	struct zone___2 node_zones[5];
	struct zonelist___2 node_zonelists[2];
	int nr_zones;
	spinlock_t node_size_lock;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct mutex kswapd_lock;
	struct task_struct___2 *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct___2 *kcompactd;
	bool proactive_compact_trigger;
	long unsigned int totalreserve_pages;
	long unsigned int min_unmapped_pages;
	long unsigned int min_slab_pages;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct deferred_split deferred_split_queue;
	unsigned int nbp_rl_start;
	long unsigned int nbp_rl_nr_cand;
	unsigned int nbp_threshold;
	unsigned int nbp_th_start;
	long unsigned int nbp_th_nr_cand;
	struct lruvec___2 __lruvec;
	long unsigned int flags;
	struct lru_gen_mm_walk___2 mm_walk;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[43];
	struct memory_tier *memtier;
	long: 64;
	long: 64;
	long: 64;
};

struct core_state___2;

struct tty_struct___2;

struct signal_struct___2 {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct___2 *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct___2 *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state___2 *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	int posix_timer_id;
	struct list_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid *pids[4];
	atomic_t tick_dep_mask;
	struct pid *tty_old_pgrp;
	int leader;
	struct tty_struct___2 *tty;
	struct autogroup *autogroup;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	unsigned int audit_tty;
	struct tty_audit_buf *tty_audit_buf;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct___2 *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct net___2;

struct nsproxy___2 {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net___2 *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct bio___2;

struct bio_list___2 {
	struct bio___2 *head;
	struct bio___2 *tail;
};

struct bdi_writeback___2 {
	struct backing_dev_info___2 *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	long unsigned int dirty_sleep;
	struct list_head bdi_node;
	struct percpu_ref refcnt;
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css;
	struct cgroup_subsys_state *blkcg_css;
	struct list_head memcg_node;
	struct list_head blkcg_node;
	struct list_head b_attached;
	struct list_head offline_node;
	union {
		struct work_struct release_work;
		struct callback_head rcu;
	};
};

struct backing_dev_info___2 {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	struct bdi_writeback___2 wb;
	struct list_head wb_list;
	struct xarray cgwb_tree;
	struct mutex cgwb_release_mutex;
	struct rw_semaphore wb_switch_rwsem;
	wait_queue_head_t wb_waitq;
	struct device___2 *dev;
	char dev_name[64];
	struct device___2 *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry___2 *debug_dir;
};

struct cgroup___2;

struct css_set___2 {
	struct cgroup_subsys_state *subsys[13];
	refcount_t refcount;
	struct css_set___2 *dom_cset;
	struct cgroup___2 *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[13];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_src_preload_node;
	struct list_head mg_dst_preload_node;
	struct list_head mg_node;
	struct cgroup___2 *mg_src_cgrp;
	struct cgroup___2 *mg_dst_cgrp;
	struct css_set___2 *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
};

struct fasync_struct___2;

struct pipe_buffer___2;

struct pipe_inode_info___2 {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	bool note_loss;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	struct page___2 *tmp_page;
	struct fasync_struct___2 *fasync_readers;
	struct fasync_struct___2 *fasync_writers;
	struct pipe_buffer___2 *bufs;
	struct user_struct *user;
	struct watch_queue *watch_queue;
};

struct vm_struct___2 {
	struct vm_struct___2 *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page___2 **pages;
	unsigned int page_order;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

struct cgroup___2 {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	struct kernfs_node___2 *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	struct cgroup_file psi_files[4];
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[13];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[13];
	struct cgroup___2 *dom_cgrp;
	struct cgroup___2 *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group *psi;
	struct cgroup_bpf bpf;
	atomic_t congestion_count;
	struct cgroup_freezer_state freezer;
	struct cgroup___2 *ancestors[0];
};

struct core_thread___2 {
	struct task_struct___2 *task;
	struct core_thread___2 *next;
};

struct core_state___2 {
	atomic_t nr_threads;
	struct core_thread___2 dumper;
	struct completion startup;
};

struct tty_struct___2 {
	struct kref kref;
	struct device___2 *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;
	struct ld_semaphore ldisc_sem;
	struct tty_ldisc *ldisc;
	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	struct ktermios termios;
	struct ktermios termios_locked;
	char name[64];
	long unsigned int flags;
	int count;
	struct winsize winsize;
	struct {
		spinlock_t lock;
		bool stopped;
		bool tco_stopped;
		long unsigned int unused[0];
	} flow;
	struct {
		spinlock_t lock;
		struct pid *pgrp;
		struct pid *session;
		unsigned char pktstatus;
		bool packet;
		long unsigned int unused[0];
	} ctrl;
	int hw_stopped;
	unsigned int receive_room;
	int flow_change;
	struct tty_struct___2 *link;
	struct fasync_struct___2 *fasync;
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	spinlock_t files_lock;
	struct list_head tty_files;
	int closing;
	unsigned char *write_buf;
	int write_cnt;
	struct work_struct SAK_work;
	struct tty_port *port;
};

struct kiocb___2 {
	struct file___2 *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb___2 *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	struct wait_page_queue *ki_waitq;
};

struct iattr___2 {
	unsigned int ia_valid;
	umode_t ia_mode;
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file___2 *ia_file;
};

struct dquot___2 {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block___2 *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};

struct quota_format_type___2 {
	int qf_fmt_id;
	const struct quota_format_ops___2 *qf_ops;
	struct module___2 *qf_owner;
	struct quota_format_type___2 *qf_next;
};

struct quota_format_ops___2 {
	int (*check_quota_file)(struct super_block___2 *, int);
	int (*read_file_info)(struct super_block___2 *, int);
	int (*write_file_info)(struct super_block___2 *, int);
	int (*free_file_info)(struct super_block___2 *, int);
	int (*read_dqblk)(struct dquot___2 *);
	int (*commit_dqblk)(struct dquot___2 *);
	int (*release_dqblk)(struct dquot___2 *);
	int (*get_next_id)(struct super_block___2 *, struct kqid *);
};

struct dquot_operations___2 {
	int (*write_dquot)(struct dquot___2 *);
	struct dquot___2 * (*alloc_dquot)(struct super_block___2 *, int);
	void (*destroy_dquot)(struct dquot___2 *);
	int (*acquire_dquot)(struct dquot___2 *);
	int (*release_dquot)(struct dquot___2 *);
	int (*mark_dirty)(struct dquot___2 *);
	int (*write_info)(struct super_block___2 *, int);
	qsize_t * (*get_reserved_space)(struct inode___2 *);
	int (*get_projid)(struct inode___2 *, kprojid_t *);
	int (*get_inode_usage)(struct inode___2 *, qsize_t *);
	int (*get_next_id)(struct super_block___2 *, struct kqid *);
};

struct quotactl_ops___2 {
	int (*quota_on)(struct super_block___2 *, int, int, const struct path___2 *);
	int (*quota_off)(struct super_block___2 *, int);
	int (*quota_enable)(struct super_block___2 *, unsigned int);
	int (*quota_disable)(struct super_block___2 *, unsigned int);
	int (*quota_sync)(struct super_block___2 *, int);
	int (*set_info)(struct super_block___2 *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block___2 *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block___2 *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block___2 *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block___2 *, struct qc_state *);
	int (*rm_xquota)(struct super_block___2 *, unsigned int);
};

struct writeback_control___2;

struct address_space_operations___2 {
	int (*writepage)(struct page___2 *, struct writeback_control___2 *);
	int (*read_folio)(struct file___2 *, struct folio___2 *);
	int (*writepages)(struct address_space___2 *, struct writeback_control___2 *);
	bool (*dirty_folio)(struct address_space___2 *, struct folio___2 *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file___2 *, struct address_space___2 *, loff_t, unsigned int, struct page___2 **, void **);
	int (*write_end)(struct file___2 *, struct address_space___2 *, loff_t, unsigned int, unsigned int, struct page___2 *, void *);
	sector_t (*bmap)(struct address_space___2 *, sector_t);
	void (*invalidate_folio)(struct folio___2 *, size_t, size_t);
	bool (*release_folio)(struct folio___2 *, gfp_t);
	void (*free_folio)(struct folio___2 *);
	ssize_t (*direct_IO)(struct kiocb___2 *, struct iov_iter___2 *);
	int (*migrate_folio)(struct address_space___2 *, struct folio___2 *, struct folio___2 *, enum migrate_mode);
	int (*launder_folio)(struct folio___2 *);
	bool (*is_partially_uptodate)(struct folio___2 *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio___2 *, bool *, bool *);
	int (*error_remove_page)(struct address_space___2 *, struct page___2 *);
	int (*swap_activate)(struct swap_info_struct *, struct file___2 *, sector_t *);
	void (*swap_deactivate)(struct file___2 *);
	int (*swap_rw)(struct kiocb___2 *, struct iov_iter___2 *);
};

struct writeback_control___2 {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_fscache_wb: 1;
	unsigned int no_cgroup_owner: 1;
	unsigned int punt_to_cgroup: 1;
	struct swap_iocb **swap_plug;
	struct bdi_writeback___2 *wb;
	struct inode___2 *inode;
	int wb_id;
	int wb_lcand_id;
	int wb_tcand_id;
	size_t wb_bytes;
	size_t wb_lcand_bytes;
	size_t wb_tcand_bytes;
};

struct bio_vec___2;

struct iov_iter___2 {
	u8 iter_type;
	bool nofault;
	bool data_source;
	bool user_backed;
	union {
		size_t iov_offset;
		int last_offset;
	};
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec___2 *bvec;
		struct xarray *xarray;
		struct pipe_inode_info___2 *pipe;
		void *ubuf;
	};
	union {
		long unsigned int nr_segs;
		struct {
			unsigned int head;
			unsigned int start_head;
		};
		loff_t xarray_start;
	};
};

struct cdev___2 {
	struct kobject___2 kobj;
	struct module___2 *owner;
	const struct file_operations___2 *ops;
	struct list_head list;
	dev_t dev;
	unsigned int count;
};

struct inode_operations___2 {
	struct dentry___2 * (*lookup)(struct inode___2 *, struct dentry___2 *, unsigned int);
	const char * (*get_link)(struct dentry___2 *, struct inode___2 *, struct delayed_call *);
	int (*permission)(struct user_namespace *, struct inode___2 *, int);
	struct posix_acl * (*get_acl)(struct inode___2 *, int, bool);
	int (*readlink)(struct dentry___2 *, char *, int);
	int (*create)(struct user_namespace *, struct inode___2 *, struct dentry___2 *, umode_t, bool);
	int (*link)(struct dentry___2 *, struct inode___2 *, struct dentry___2 *);
	int (*unlink)(struct inode___2 *, struct dentry___2 *);
	int (*symlink)(struct user_namespace *, struct inode___2 *, struct dentry___2 *, const char *);
	int (*mkdir)(struct user_namespace *, struct inode___2 *, struct dentry___2 *, umode_t);
	int (*rmdir)(struct inode___2 *, struct dentry___2 *);
	int (*mknod)(struct user_namespace *, struct inode___2 *, struct dentry___2 *, umode_t, dev_t);
	int (*rename)(struct user_namespace *, struct inode___2 *, struct dentry___2 *, struct inode___2 *, struct dentry___2 *, unsigned int);
	int (*setattr)(struct user_namespace *, struct dentry___2 *, struct iattr___2 *);
	int (*getattr)(struct user_namespace *, const struct path___2 *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry___2 *, char *, size_t);
	int (*fiemap)(struct inode___2 *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode___2 *, struct timespec64 *, int);
	int (*atomic_open)(struct inode___2 *, struct dentry___2 *, struct file___2 *, unsigned int, umode_t);
	int (*tmpfile)(struct user_namespace *, struct inode___2 *, struct file___2 *, umode_t);
	int (*set_acl)(struct user_namespace *, struct inode___2 *, struct posix_acl *, int);
	int (*fileattr_set)(struct user_namespace *, struct dentry___2 *, struct fileattr *);
	int (*fileattr_get)(struct dentry___2 *, struct fileattr *);
	long: 64;
};

struct file_lock_operations___2 {
	void (*fl_copy_lock)(struct file_lock___2 *, struct file_lock___2 *);
	void (*fl_release_private)(struct file_lock___2 *);
};

struct lock_manager_operations___2;

struct file_lock___2 {
	struct file_lock___2 *fl_blocker;
	struct list_head fl_list;
	struct hlist_node fl_link;
	struct list_head fl_blocked_requests;
	struct list_head fl_blocked_member;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	unsigned int fl_pid;
	int fl_link_cpu;
	wait_queue_head_t fl_wait;
	struct file___2 *fl_file;
	loff_t fl_start;
	loff_t fl_end;
	struct fasync_struct___2 *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct file_lock_operations___2 *fl_ops;
	const struct lock_manager_operations___2 *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
	} fl_u;
};

struct lock_manager_operations___2 {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock___2 *);
	int (*lm_grant)(struct file_lock___2 *, int);
	bool (*lm_break)(struct file_lock___2 *);
	int (*lm_change)(struct file_lock___2 *, int, struct list_head *);
	void (*lm_setup)(struct file_lock___2 *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lock___2 *);
	bool (*lm_lock_expirable)(struct file_lock___2 *);
	void (*lm_expire_lock)();
};

struct fasync_struct___2 {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct___2 *fa_next;
	struct file___2 *fa_file;
	struct callback_head fa_rcu;
};

struct super_operations___2 {
	struct inode___2 * (*alloc_inode)(struct super_block___2 *);
	void (*destroy_inode)(struct inode___2 *);
	void (*free_inode)(struct inode___2 *);
	void (*dirty_inode)(struct inode___2 *, int);
	int (*write_inode)(struct inode___2 *, struct writeback_control___2 *);
	int (*drop_inode)(struct inode___2 *);
	void (*evict_inode)(struct inode___2 *);
	void (*put_super)(struct super_block___2 *);
	int (*sync_fs)(struct super_block___2 *, int);
	int (*freeze_super)(struct super_block___2 *);
	int (*freeze_fs)(struct super_block___2 *);
	int (*thaw_super)(struct super_block___2 *);
	int (*unfreeze_fs)(struct super_block___2 *);
	int (*statfs)(struct dentry___2 *, struct kstatfs *);
	int (*remount_fs)(struct super_block___2 *, int *, char *);
	void (*umount_begin)(struct super_block___2 *);
	int (*show_options)(struct seq_file___2 *, struct dentry___2 *);
	int (*show_devname)(struct seq_file___2 *, struct dentry___2 *);
	int (*show_path)(struct seq_file___2 *, struct dentry___2 *);
	int (*show_stats)(struct seq_file___2 *, struct dentry___2 *);
	ssize_t (*quota_read)(struct super_block___2 *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block___2 *, int, const char *, size_t, loff_t);
	struct dquot___2 ** (*get_dquots)(struct inode___2 *);
	long int (*nr_cached_objects)(struct super_block___2 *, struct shrink_control___2 *);
	long int (*free_cached_objects)(struct super_block___2 *, struct shrink_control___2 *);
};

struct wakeup_source___2;

struct dev_pm_info___2 {
	pm_message_t power_state;
	unsigned int can_wakeup: 1;
	unsigned int async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	struct list_head entry;
	struct completion completion;
	struct wakeup_source___2 *wakeup;
	bool wakeup_path: 1;
	bool syscore: 1;
	bool no_pm_callbacks: 1;
	unsigned int must_resume: 1;
	unsigned int may_skip_resume: 1;
	struct hrtimer suspend_timer;
	u64 timer_expires;
	struct work_struct work;
	wait_queue_head_t wait_queue;
	struct wake_irq *wakeirq;
	atomic_t usage_count;
	atomic_t child_count;
	unsigned int disable_depth: 3;
	unsigned int idle_notification: 1;
	unsigned int request_pending: 1;
	unsigned int deferred_resume: 1;
	unsigned int needs_force_resume: 1;
	unsigned int runtime_auto: 1;
	bool ignore_children: 1;
	unsigned int no_callbacks: 1;
	unsigned int irq_safe: 1;
	unsigned int use_autosuspend: 1;
	unsigned int timer_autosuspends: 1;
	unsigned int memalloc_noio: 1;
	unsigned int links_count;
	enum rpm_request request;
	enum rpm_status runtime_status;
	enum rpm_status last_status;
	int runtime_error;
	int autosuspend_delay;
	u64 last_busy;
	u64 active_time;
	u64 suspended_time;
	u64 accounting_timestamp;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device___2 *, s32);
	struct dev_pm_qos *qos;
};

struct device_type___2;

struct bus_type___2;

struct device_driver___2;

struct dev_pm_domain___2;

struct fwnode_handle___2;

struct class___2;

struct device___2 {
	struct kobject___2 kobj;
	struct device___2 *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type___2 *type;
	struct bus_type___2 *bus;
	struct device_driver___2 *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info___2 power;
	struct dev_pm_domain___2 *pm_domain;
	struct em_perf_domain *em_pd;
	struct dev_pin_info *pins;
	struct dev_msi_info msi;
	const struct dma_map_ops *dma_ops;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct cma *cma_area;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle___2 *fwnode;
	int numa_node;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	struct class___2 *class;
	const struct attribute_group___2 **groups;
	void (*release)(struct device___2 *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
};

struct block_device___2 {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	bool bd_read_only;
	dev_t bd_dev;
	atomic_t bd_openers;
	struct inode___2 *bd_inode;
	struct super_block___2 *bd_super;
	void *bd_claiming;
	struct device___2 bd_device;
	void *bd_holder;
	int bd_holders;
	bool bd_write_holder;
	struct kobject___2 *bd_holder_dir;
	u8 bd_partno;
	spinlock_t bd_size_lock;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	int bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct super_block___2 *bd_fsfreeze_sb;
	struct partition_meta_info *bd_meta_info;
};

typedef void (*poll_queue_proc___2)(struct file___2 *, wait_queue_head_t *, struct poll_table_struct___2 *);

struct poll_table_struct___2 {
	poll_queue_proc___2 _qproc;
	__poll_t _key;
};

struct seq_file___2 {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations___2 *op;
	int poll_event;
	const struct file___2 *file;
	void *private;
};

typedef void bio_end_io_t___2(struct bio___2 *);

struct bio_vec___2 {
	struct page___2 *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct bio___2 {
	struct bio___2 *bi_next;
	struct block_device___2 *bi_bdev;
	blk_opf_t bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t___2 *bi_end_io;
	void *bi_private;
	struct blkcg_gq *bi_blkg;
	struct bio_issue bi_issue;
	u64 bi_iocost_cost;
	struct bio_crypt_ctx *bi_crypt_context;
	union {
		struct bio_integrity_payload *bi_integrity;
	};
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec___2 *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec___2 bi_inline_vecs[0];
};

struct dev_pagemap_ops___2 {
	void (*page_free)(struct page___2 *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault___2 *);
	int (*memory_failure)(struct dev_pagemap___2 *, long unsigned int, long unsigned int, int);
};

struct ubuf_info___2;

struct sock___2;

struct sk_buff___2;

struct msghdr___2 {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter___2 msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb___2 *msg_iocb;
	struct ubuf_info___2 *msg_ubuf;
	int (*sg_from_iter)(struct sock___2 *, struct sk_buff___2 *, struct iov_iter___2 *, size_t);
};

struct ubuf_info___2 {
	void (*callback)(struct sk_buff___2 *, struct ubuf_info___2 *, bool);
	refcount_t refcnt;
	u8 flags;
};

struct sk_buff_list___2 {
	struct sk_buff___2 *next;
	struct sk_buff___2 *prev;
};

struct sk_buff_head___2 {
	union {
		struct {
			struct sk_buff___2 *next;
			struct sk_buff___2 *prev;
		};
		struct sk_buff_list___2 list;
	};
	__u32 qlen;
	spinlock_t lock;
};

struct socket___2;

struct net_device___2;

struct sock___2 {
	struct sock_common __sk_common;
	struct dst_entry *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	socket_lock_t sk_lock;
	atomic_t sk_drops;
	int sk_rcvlowat;
	struct sk_buff_head___2 sk_error_queue;
	struct sk_buff_head___2 sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	int sk_forward_alloc;
	u32 sk_reserved_mem;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	int sk_rcvbuf;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	struct xfrm_policy *sk_policy[2];
	struct dst_entry *sk_dst_cache;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head___2 sk_write_queue;
	__s32 sk_peek_off;
	int sk_write_pending;
	__u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	long int sk_sndtimeo;
	struct timer_list sk_timer;
	__u32 sk_priority;
	__u32 sk_mark;
	long unsigned int sk_pacing_rate;
	long unsigned int sk_max_pacing_rate;
	struct page_frag___2 sk_frag;
	netdev_features_t sk_route_caps;
	int sk_gso_type;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	__u32 sk_txhash;
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_userlocks: 4;
	u8 sk_pacing_shift;
	u16 sk_type;
	u16 sk_protocol;
	u16 sk_gso_max_segs;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	u8 sk_txrehash;
	u8 sk_prefer_busy_poll;
	u16 sk_busy_poll_budget;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid *sk_peer_pid;
	const struct cred *sk_peer_cred;
	long int sk_rcvtimeo;
	ktime_t sk_stamp;
	u16 sk_tsflags;
	u8 sk_shutdown;
	atomic_t sk_tskey;
	atomic_t sk_zckey;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	struct socket___2 *sk_socket;
	void *sk_user_data;
	void *sk_security;
	struct sock_cgroup_data sk_cgrp_data;
	struct mem_cgroup___2 *sk_memcg;
	void (*sk_state_change)(struct sock___2 *);
	void (*sk_data_ready)(struct sock___2 *);
	void (*sk_write_space)(struct sock___2 *);
	void (*sk_error_report)(struct sock___2 *);
	int (*sk_backlog_rcv)(struct sock___2 *, struct sk_buff___2 *);
	struct sk_buff___2 * (*sk_validate_xmit_skb)(struct sock___2 *, struct net_device___2 *, struct sk_buff___2 *);
	void (*sk_destruct)(struct sock___2 *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
	struct hlist_node sk_bind2_node;
};

struct sk_buff___2 {
	union {
		struct {
			struct sk_buff___2 *next;
			struct sk_buff___2 *prev;
			union {
				struct net_device___2 *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	union {
		struct sock___2 *sk;
		int ip_defrag_offset;
	};
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff___2 *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};

struct socket_wq___2 {
	wait_queue_head_t wait;
	struct fasync_struct___2 *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
	long: 64;
};

struct proto_ops___2;

struct socket___2 {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file___2 *file;
	struct sock___2 *sk;
	const struct proto_ops___2 *ops;
	long: 64;
	long: 64;
	long: 64;
	struct socket_wq___2 wq;
};

typedef int (*sk_read_actor_t___2)(read_descriptor_t *, struct sk_buff___2 *, unsigned int, size_t);

typedef int (*skb_read_actor_t___2)(struct sock___2 *, struct sk_buff___2 *);

struct proto_ops___2 {
	int family;
	struct module___2 *owner;
	int (*release)(struct socket___2 *);
	int (*bind)(struct socket___2 *, struct sockaddr *, int);
	int (*connect)(struct socket___2 *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket___2 *, struct socket___2 *);
	int (*accept)(struct socket___2 *, struct socket___2 *, int, bool);
	int (*getname)(struct socket___2 *, struct sockaddr *, int);
	__poll_t (*poll)(struct file___2 *, struct socket___2 *, struct poll_table_struct___2 *);
	int (*ioctl)(struct socket___2 *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct socket___2 *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket___2 *, void *, bool, bool);
	int (*listen)(struct socket___2 *, int);
	int (*shutdown)(struct socket___2 *, int);
	int (*setsockopt)(struct socket___2 *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket___2 *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file___2 *, struct socket___2 *);
	int (*sendmsg)(struct socket___2 *, struct msghdr___2 *, size_t);
	int (*recvmsg)(struct socket___2 *, struct msghdr___2 *, size_t, int);
	int (*mmap)(struct file___2 *, struct socket___2 *, struct vm_area_struct___2 *);
	ssize_t (*sendpage)(struct socket___2 *, struct page___2 *, int, size_t, int);
	ssize_t (*splice_read)(struct socket___2 *, loff_t *, struct pipe_inode_info___2 *, size_t, unsigned int);
	int (*set_peek_off)(struct sock___2 *, int);
	int (*peek_len)(struct socket___2 *);
	int (*read_sock)(struct sock___2 *, read_descriptor_t *, sk_read_actor_t___2);
	int (*read_skb)(struct sock___2 *, skb_read_actor_t___2);
	int (*sendpage_locked)(struct sock___2 *, struct page___2 *, int, size_t, int);
	int (*sendmsg_locked)(struct sock___2 *, struct msghdr___2 *, size_t);
	int (*set_rcvlowat)(struct sock___2 *, int);
};

struct net___2 {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	atomic_t dev_unreg_count;
	unsigned int dev_base_seq;
	int ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node cleanup_list;
	struct key_tag *key_domain;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
	struct sock___2 *rtnl;
	struct sock___2 *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device___2 *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_ipv4 ipv4;
	struct netns_ipv6 ipv6;
	struct netns_ieee802154_lowpan ieee802154_lowpan;
	struct netns_sctp sctp;
	struct netns_nf nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct netns_ft ft;
	struct sk_buff_head___2 wext_nlevents;
	struct net_generic *gen;
	struct netns_bpf bpf;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_xfrm xfrm;
	u64 net_cookie;
	struct netns_ipvs *ipvs;
	struct netns_mpls mpls;
	struct netns_can can;
	struct netns_xdp xdp;
	struct netns_mctp mctp;
	struct sock___2 *crypto_nlsk;
	struct sock___2 *diag_nlsk;
	struct netns_smc smc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct kernfs_elem_symlink___2 {
	struct kernfs_node___2 *target_kn;
};

struct kernfs_ops___2;

struct kernfs_elem_attr___2 {
	const struct kernfs_ops___2 *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node___2 *notify_next;
};

struct kernfs_node___2 {
	atomic_t count;
	atomic_t active;
	struct kernfs_node___2 *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink___2 symlink;
		struct kernfs_elem_attr___2 attr;
	};
	void *priv;
	u64 id;
	short unsigned int flags;
	umode_t mode;
	struct kernfs_iattrs *iattr;
};

struct kernfs_open_file___2;

struct kernfs_ops___2 {
	int (*open)(struct kernfs_open_file___2 *);
	void (*release)(struct kernfs_open_file___2 *);
	int (*seq_show)(struct seq_file___2 *, void *);
	void * (*seq_start)(struct seq_file___2 *, loff_t *);
	void * (*seq_next)(struct seq_file___2 *, void *, loff_t *);
	void (*seq_stop)(struct seq_file___2 *, void *);
	ssize_t (*read)(struct kernfs_open_file___2 *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file___2 *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file___2 *, struct poll_table_struct___2 *);
	int (*mmap)(struct kernfs_open_file___2 *, struct vm_area_struct___2 *);
};

struct kernfs_open_file___2 {
	struct kernfs_node___2 *kn;
	struct file___2 *file;
	struct seq_file___2 *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct___2 *vm_ops;
};

struct kobj_ns_type_operations___2 {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock___2 *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

struct bin_attribute___2 {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space___2 * (*f_mapping)();
	ssize_t (*read)(struct file___2 *, struct kobject___2 *, struct bin_attribute___2 *, char *, loff_t, size_t);
	ssize_t (*write)(struct file___2 *, struct kobject___2 *, struct bin_attribute___2 *, char *, loff_t, size_t);
	int (*mmap)(struct file___2 *, struct kobject___2 *, struct bin_attribute___2 *, struct vm_area_struct___2 *);
};

struct sysfs_ops___2 {
	ssize_t (*show)(struct kobject___2 *, struct attribute *, char *);
	ssize_t (*store)(struct kobject___2 *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops___2;

struct kset___2 {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject___2 kobj;
	const struct kset_uevent_ops___2 *uevent_ops;
};

struct kobj_type___2 {
	void (*release)(struct kobject___2 *);
	const struct sysfs_ops___2 *sysfs_ops;
	const struct attribute_group___2 **default_groups;
	const struct kobj_ns_type_operations___2 * (*child_ns_type)(struct kobject___2 *);
	const void * (*namespace)(struct kobject___2 *);
	void (*get_ownership)(struct kobject___2 *, kuid_t *, kgid_t *);
};

struct kset_uevent_ops___2 {
	int (* const filter)(struct kobject___2 *);
	const char * (* const name)(struct kobject___2 *);
	int (* const uevent)(struct kobject___2 *, struct kobj_uevent_env *);
};

struct dev_pm_ops___2 {
	int (*prepare)(struct device___2 *);
	void (*complete)(struct device___2 *);
	int (*suspend)(struct device___2 *);
	int (*resume)(struct device___2 *);
	int (*freeze)(struct device___2 *);
	int (*thaw)(struct device___2 *);
	int (*poweroff)(struct device___2 *);
	int (*restore)(struct device___2 *);
	int (*suspend_late)(struct device___2 *);
	int (*resume_early)(struct device___2 *);
	int (*freeze_late)(struct device___2 *);
	int (*thaw_early)(struct device___2 *);
	int (*poweroff_late)(struct device___2 *);
	int (*restore_early)(struct device___2 *);
	int (*suspend_noirq)(struct device___2 *);
	int (*resume_noirq)(struct device___2 *);
	int (*freeze_noirq)(struct device___2 *);
	int (*thaw_noirq)(struct device___2 *);
	int (*poweroff_noirq)(struct device___2 *);
	int (*restore_noirq)(struct device___2 *);
	int (*runtime_suspend)(struct device___2 *);
	int (*runtime_resume)(struct device___2 *);
	int (*runtime_idle)(struct device___2 *);
};

struct wakeup_source___2 {
	const char *name;
	int id;
	struct list_head entry;
	spinlock_t lock;
	struct wake_irq *wakeirq;
	struct timer_list timer;
	long unsigned int timer_expires;
	ktime_t total_time;
	ktime_t max_time;
	ktime_t last_time;
	ktime_t start_prevent_time;
	ktime_t prevent_sleep_time;
	long unsigned int event_count;
	long unsigned int active_count;
	long unsigned int relax_count;
	long unsigned int expire_count;
	long unsigned int wakeup_count;
	struct device___2 *dev;
	bool active: 1;
	bool autosleep_enabled: 1;
};

struct dev_pm_domain___2 {
	struct dev_pm_ops___2 ops;
	int (*start)(struct device___2 *);
	void (*detach)(struct device___2 *, bool);
	int (*activate)(struct device___2 *);
	void (*sync)(struct device___2 *);
	void (*dismiss)(struct device___2 *);
};

struct bus_type___2 {
	const char *name;
	const char *dev_name;
	struct device___2 *dev_root;
	const struct attribute_group___2 **bus_groups;
	const struct attribute_group___2 **dev_groups;
	const struct attribute_group___2 **drv_groups;
	int (*match)(struct device___2 *, struct device_driver___2 *);
	int (*uevent)(struct device___2 *, struct kobj_uevent_env *);
	int (*probe)(struct device___2 *);
	void (*sync_state)(struct device___2 *);
	void (*remove)(struct device___2 *);
	void (*shutdown)(struct device___2 *);
	int (*online)(struct device___2 *);
	int (*offline)(struct device___2 *);
	int (*suspend)(struct device___2 *, pm_message_t);
	int (*resume)(struct device___2 *);
	int (*num_vf)(struct device___2 *);
	int (*dma_configure)(struct device___2 *);
	void (*dma_cleanup)(struct device___2 *);
	const struct dev_pm_ops___2 *pm;
	const struct iommu_ops *iommu_ops;
	struct subsys_private *p;
	struct lock_class_key lock_key;
	bool need_parent_lock;
};

struct device_driver___2 {
	const char *name;
	struct bus_type___2 *bus;
	struct module___2 *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device___2 *);
	void (*sync_state)(struct device___2 *);
	int (*remove)(struct device___2 *);
	void (*shutdown)(struct device___2 *);
	int (*suspend)(struct device___2 *, pm_message_t);
	int (*resume)(struct device___2 *);
	const struct attribute_group___2 **groups;
	const struct attribute_group___2 **dev_groups;
	const struct dev_pm_ops___2 *pm;
	void (*coredump)(struct device___2 *);
	struct driver_private *p;
};

struct device_type___2 {
	const char *name;
	const struct attribute_group___2 **groups;
	int (*uevent)(struct device___2 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___2 *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device___2 *);
	const struct dev_pm_ops___2 *pm;
};

struct class___2 {
	const char *name;
	struct module___2 *owner;
	const struct attribute_group___2 **class_groups;
	const struct attribute_group___2 **dev_groups;
	struct kobject___2 *dev_kobj;
	int (*dev_uevent)(struct device___2 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___2 *, umode_t *);
	void (*class_release)(struct class___2 *);
	void (*dev_release)(struct device___2 *);
	int (*shutdown_pre)(struct device___2 *);
	const struct kobj_ns_type_operations___2 *ns_type;
	const void * (*namespace)(struct device___2 *);
	void (*get_ownership)(struct device___2 *, kuid_t *, kgid_t *);
	const struct dev_pm_ops___2 *pm;
	struct subsys_private *p;
};

struct kparam_array___2;

struct kernel_param___2 {
	const char *name;
	struct module___2 *mod;
	const struct kernel_param_ops___2 *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array___2 *arr;
	};
};

struct kparam_array___2 {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops___2 *ops;
	void *elem;
};

struct module_attribute___2 {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute___2 *, struct module_kobject___2 *, char *);
	ssize_t (*store)(struct module_attribute___2 *, struct module_kobject___2 *, const char *, size_t);
	void (*setup)(struct module___2 *, const char *);
	int (*test)(struct module___2 *);
	void (*free)(struct module___2 *);
};

struct fwnode_operations___2;

struct fwnode_handle___2 {
	struct fwnode_handle___2 *secondary;
	const struct fwnode_operations___2 *ops;
	struct device___2 *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

struct fwnode_reference_args___2;

struct fwnode_endpoint___2;

struct fwnode_operations___2 {
	struct fwnode_handle___2 * (*get)(struct fwnode_handle___2 *);
	void (*put)(struct fwnode_handle___2 *);
	bool (*device_is_available)(const struct fwnode_handle___2 *);
	const void * (*device_get_match_data)(const struct fwnode_handle___2 *, const struct device___2 *);
	bool (*device_dma_supported)(const struct fwnode_handle___2 *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle___2 *);
	bool (*property_present)(const struct fwnode_handle___2 *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle___2 *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle___2 *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle___2 *);
	const char * (*get_name_prefix)(const struct fwnode_handle___2 *);
	struct fwnode_handle___2 * (*get_parent)(const struct fwnode_handle___2 *);
	struct fwnode_handle___2 * (*get_next_child_node)(const struct fwnode_handle___2 *, struct fwnode_handle___2 *);
	struct fwnode_handle___2 * (*get_named_child_node)(const struct fwnode_handle___2 *, const char *);
	int (*get_reference_args)(const struct fwnode_handle___2 *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args___2 *);
	struct fwnode_handle___2 * (*graph_get_next_endpoint)(const struct fwnode_handle___2 *, struct fwnode_handle___2 *);
	struct fwnode_handle___2 * (*graph_get_remote_endpoint)(const struct fwnode_handle___2 *);
	struct fwnode_handle___2 * (*graph_get_port_parent)(struct fwnode_handle___2 *);
	int (*graph_parse_endpoint)(const struct fwnode_handle___2 *, struct fwnode_endpoint___2 *);
	void * (*iomap)(struct fwnode_handle___2 *, int);
	int (*irq_get)(const struct fwnode_handle___2 *, unsigned int);
	int (*add_links)(struct fwnode_handle___2 *);
};

struct fwnode_endpoint___2 {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle___2 *local_fwnode;
};

struct fwnode_reference_args___2 {
	struct fwnode_handle___2 *fwnode;
	unsigned int nargs;
	u64 args[8];
};

struct pipe_buf_operations___2;

struct pipe_buffer___2 {
	struct page___2 *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations___2 *ops;
	unsigned int flags;
	long unsigned int private;
};

struct pipe_buf_operations___2 {
	int (*confirm)(struct pipe_inode_info___2 *, struct pipe_buffer___2 *);
	void (*release)(struct pipe_inode_info___2 *, struct pipe_buffer___2 *);
	bool (*try_steal)(struct pipe_inode_info___2 *, struct pipe_buffer___2 *);
	bool (*get)(struct pipe_inode_info___2 *, struct pipe_buffer___2 *);
};

typedef rx_handler_result_t rx_handler_func_t___2(struct sk_buff___2 **);

struct net_device___2 {
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
	long unsigned int state;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct list_head ptype_specific;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	unsigned int flags;
	long long unsigned int priv_flags;
	const struct net_device_ops *netdev_ops;
	int ifindex;
	short unsigned int gflags;
	short unsigned int hard_header_len;
	unsigned int mtu;
	short unsigned int needed_headroom;
	short unsigned int needed_tailroom;
	netdev_features_t features;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	netdev_features_t gso_partial_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct iw_handler_def *wireless_handlers;
	struct iw_public_data *wireless_data;
	const struct ethtool_ops *ethtool_ops;
	const struct l3mdev_ops *l3mdev_ops;
	const struct ndisc_ops *ndisc_ops;
	const struct xfrmdev_ops *xfrmdev_ops;
	const struct tlsdev_ops *tlsdev_ops;
	const struct header_ops *header_ops;
	unsigned char operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	short unsigned int padded;
	spinlock_t addr_list_lock;
	int irq;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset___2 *queues_kset;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct inet6_dev *ip6_ptr;
	struct vlan_info *vlan_info;
	struct dsa_port *dsa_ptr;
	struct tipc_bearer *tipc_ptr;
	void *atalk_ptr;
	void *ax25_ptr;
	struct wireless_dev *ieee80211_ptr;
	struct wpan_dev *ieee802154_ptr;
	struct mpls_dev *mpls_ptr;
	struct mctp_dev *mctp_ptr;
	const unsigned char *dev_addr;
	struct netdev_rx_queue *_rx;
	unsigned int num_rx_queues;
	unsigned int real_num_rx_queues;
	struct bpf_prog *xdp_prog;
	long unsigned int gro_flush_timeout;
	int napi_defer_hard_irqs;
	unsigned int gro_max_size;
	rx_handler_func_t___2 *rx_handler;
	void *rx_handler_data;
	struct mini_Qdisc *miniq_ingress;
	struct netdev_queue *ingress_queue;
	struct nf_hook_entries *nf_hooks_ingress;
	unsigned char broadcast[32];
	struct cpu_rmap *rx_cpu_rmap;
	struct hlist_node index_hlist;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netdev_queue *_tx;
	unsigned int num_tx_queues;
	unsigned int real_num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct xps_dev_maps *xps_maps[2];
	struct mini_Qdisc *miniq_egress;
	struct nf_hook_entries *nf_hooks_egress;
	struct hlist_head qdisc_hash[16];
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	int *pcpu_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	enum {
		NETREG_UNINITIALIZED___2 = 0,
		NETREG_REGISTERED___2 = 1,
		NETREG_UNREGISTERING___2 = 2,
		NETREG_UNREGISTERED___2 = 3,
		NETREG_RELEASED___2 = 4,
		NETREG_DUMMY___2 = 5,
	} reg_state: 8;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED___2 = 0,
		RTNL_LINK_INITIALIZING___2 = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device___2 *);
	struct netpoll_info *npinfo;
	possible_net_t nd_net;
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	struct garp_port *garp_port;
	struct mrp_port *mrp_port;
	struct dm_hw_stat_delta *dm_private;
	struct device___2 dev;
	const struct attribute_group___2 *sysfs_groups[4];
	const struct attribute_group___2 *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	unsigned int gso_max_size;
	unsigned int tso_max_size;
	u16 gso_max_segs;
	u16 tso_max_segs;
	const struct dcbnl_rtnl_ops *dcbnl_ops;
	s16 num_tc;
	struct netdev_tc_txq tc_to_txq[16];
	u8 prio_tc_map[16];
	unsigned int fcoe_ddp_xid;
	struct netprio_map *priomap;
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	unsigned int wol_enabled: 1;
	unsigned int threaded: 1;
	struct list_head net_notifier_list;
	const struct macsec_ops *macsec_ops;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	long: 64;
	long: 64;
	long: 64;
};

typedef struct bio_vec___2 skb_frag_t___2;

struct skb_shared_info___2 {
	__u8 flags;
	__u8 meta_len;
	__u8 nr_frags;
	__u8 tx_flags;
	short unsigned int gso_size;
	short unsigned int gso_segs;
	struct sk_buff___2 *frag_list;
	struct skb_shared_hwtstamps hwtstamps;
	unsigned int gso_type;
	u32 tskey;
	atomic_t dataref;
	unsigned int xdp_frags_size;
	void *destructor_arg;
	skb_frag_t___2 frags[17];
};

enum ovs_packet_cmd {
	OVS_PACKET_CMD_UNSPEC = 0,
	OVS_PACKET_CMD_MISS = 1,
	OVS_PACKET_CMD_ACTION = 2,
	OVS_PACKET_CMD_EXECUTE = 3,
};

enum ovs_vport_type {
	OVS_VPORT_TYPE_UNSPEC = 0,
	OVS_VPORT_TYPE_NETDEV = 1,
	OVS_VPORT_TYPE_INTERNAL = 2,
	OVS_VPORT_TYPE_GRE = 3,
	OVS_VPORT_TYPE_VXLAN = 4,
	OVS_VPORT_TYPE_GENEVE = 5,
	__OVS_VPORT_TYPE_MAX = 6,
};

struct ovs_flow_stats {
	__u64 n_packets;
	__u64 n_bytes;
};

struct ovs_key_ethernet {
	__u8 eth_src[6];
	__u8 eth_dst[6];
};

struct ovs_key_ipv4 {
	__be32 ipv4_src;
	__be32 ipv4_dst;
	__u8 ipv4_proto;
	__u8 ipv4_tos;
	__u8 ipv4_ttl;
	__u8 ipv4_frag;
};

struct ovs_key_ipv6 {
	__be32 ipv6_src[4];
	__be32 ipv6_dst[4];
	__be32 ipv6_label;
	__u8 ipv6_proto;
	__u8 ipv6_tclass;
	__u8 ipv6_hlimit;
	__u8 ipv6_frag;
};

struct ovs_key_tcp {
	__be16 tcp_src;
	__be16 tcp_dst;
};

struct ovs_key_udp {
	__be16 udp_src;
	__be16 udp_dst;
};

struct ovs_key_sctp {
	__be16 sctp_src;
	__be16 sctp_dst;
};

struct sample_arg {
	bool exec;
	u32 probability;
};

enum ovs_userspace_attr {
	OVS_USERSPACE_ATTR_UNSPEC = 0,
	OVS_USERSPACE_ATTR_PID = 1,
	OVS_USERSPACE_ATTR_USERDATA = 2,
	OVS_USERSPACE_ATTR_EGRESS_TUN_PORT = 3,
	OVS_USERSPACE_ATTR_ACTIONS = 4,
	__OVS_USERSPACE_ATTR_MAX = 5,
};

struct ovs_action_trunc {
	__u32 max_len;
};

struct ovs_action_push_mpls {
	__be32 mpls_lse;
	__be16 mpls_ethertype;
};

struct ovs_action_add_mpls {
	__be32 mpls_lse;
	__be16 mpls_ethertype;
	__u16 tun_flags;
};

struct ovs_action_push_vlan {
	__be16 vlan_tpid;
	__be16 vlan_tci;
};

struct ovs_action_hash {
	__u32 hash_alg;
	__u32 hash_basis;
};

struct ovs_action_push_eth {
	struct ovs_key_ethernet addresses;
};

struct check_pkt_len_arg {
	u16 pkt_len;
	bool exec_for_greater;
	bool exec_for_lesser_equal;
};

enum ovs_action_attr {
	OVS_ACTION_ATTR_UNSPEC = 0,
	OVS_ACTION_ATTR_OUTPUT = 1,
	OVS_ACTION_ATTR_USERSPACE = 2,
	OVS_ACTION_ATTR_SET = 3,
	OVS_ACTION_ATTR_PUSH_VLAN = 4,
	OVS_ACTION_ATTR_POP_VLAN = 5,
	OVS_ACTION_ATTR_SAMPLE = 6,
	OVS_ACTION_ATTR_RECIRC = 7,
	OVS_ACTION_ATTR_HASH = 8,
	OVS_ACTION_ATTR_PUSH_MPLS = 9,
	OVS_ACTION_ATTR_POP_MPLS = 10,
	OVS_ACTION_ATTR_SET_MASKED = 11,
	OVS_ACTION_ATTR_CT = 12,
	OVS_ACTION_ATTR_TRUNC = 13,
	OVS_ACTION_ATTR_PUSH_ETH = 14,
	OVS_ACTION_ATTR_POP_ETH = 15,
	OVS_ACTION_ATTR_CT_CLEAR = 16,
	OVS_ACTION_ATTR_PUSH_NSH = 17,
	OVS_ACTION_ATTR_POP_NSH = 18,
	OVS_ACTION_ATTR_METER = 19,
	OVS_ACTION_ATTR_CLONE = 20,
	OVS_ACTION_ATTR_CHECK_PKT_LEN = 21,
	OVS_ACTION_ATTR_ADD_MPLS = 22,
	OVS_ACTION_ATTR_DEC_TTL = 23,
	__OVS_ACTION_ATTR_MAX = 24,
	OVS_ACTION_ATTR_SET_TO_MASKED = 25,
};

struct fqdir___2 {
	long int high_thresh;
	long int low_thresh;
	int timeout;
	int max_dist;
	struct inet_frags *f;
	struct net___2 *net;
	bool dead;
	long: 56;
	long: 64;
	long: 64;
	struct rhashtable rhashtable;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t mem;
	struct work_struct destroy_work;
	struct llist_node free_list;
	long: 64;
	long: 64;
};

struct sctp_mib {
	long unsigned int mibs[34];
};

enum {
	SCTP_MIB_NUM = 0,
	SCTP_MIB_CURRESTAB = 1,
	SCTP_MIB_ACTIVEESTABS = 2,
	SCTP_MIB_PASSIVEESTABS = 3,
	SCTP_MIB_ABORTEDS = 4,
	SCTP_MIB_SHUTDOWNS = 5,
	SCTP_MIB_OUTOFBLUES = 6,
	SCTP_MIB_CHECKSUMERRORS = 7,
	SCTP_MIB_OUTCTRLCHUNKS = 8,
	SCTP_MIB_OUTORDERCHUNKS = 9,
	SCTP_MIB_OUTUNORDERCHUNKS = 10,
	SCTP_MIB_INCTRLCHUNKS = 11,
	SCTP_MIB_INORDERCHUNKS = 12,
	SCTP_MIB_INUNORDERCHUNKS = 13,
	SCTP_MIB_FRAGUSRMSGS = 14,
	SCTP_MIB_REASMUSRMSGS = 15,
	SCTP_MIB_OUTSCTPPACKS = 16,
	SCTP_MIB_INSCTPPACKS = 17,
	SCTP_MIB_T1_INIT_EXPIREDS = 18,
	SCTP_MIB_T1_COOKIE_EXPIREDS = 19,
	SCTP_MIB_T2_SHUTDOWN_EXPIREDS = 20,
	SCTP_MIB_T3_RTX_EXPIREDS = 21,
	SCTP_MIB_T4_RTO_EXPIREDS = 22,
	SCTP_MIB_T5_SHUTDOWN_GUARD_EXPIREDS = 23,
	SCTP_MIB_DELAY_SACK_EXPIREDS = 24,
	SCTP_MIB_AUTOCLOSE_EXPIREDS = 25,
	SCTP_MIB_T1_RETRANSMITS = 26,
	SCTP_MIB_T3_RETRANSMITS = 27,
	SCTP_MIB_PMTUD_RETRANSMITS = 28,
	SCTP_MIB_FAST_RETRANSMITS = 29,
	SCTP_MIB_IN_PKT_SOFTIRQ = 30,
	SCTP_MIB_IN_PKT_BACKLOG = 31,
	SCTP_MIB_IN_PKT_DISCARDS = 32,
	SCTP_MIB_IN_DATA_CHUNK_DISCARDS = 33,
	__SCTP_MIB_MAX = 34,
};

struct nsh_md1_ctx {
	__be32 context[4];
};

struct nsh_md2_tlv {
	__be16 md_class;
	u8 type;
	u8 length;
	u8 md_value[0];
};

struct nshhdr {
	__be16 ver_flags_ttl_len;
	u8 mdtype;
	u8 np;
	__be32 path_hdr;
	union {
		struct nsh_md1_ctx md1;
		struct nsh_md2_tlv md2;
	};
};

enum sw_flow_mac_proto {
	MAC_PROTO_NONE = 0,
	MAC_PROTO_ETHERNET = 1,
};

struct ovs_tunnel_info {
	struct metadata_dst *tun_dst;
};

struct dp_meter_band {
	u32 type;
	u32 rate;
	u32 burst_size;
	u64 bucket;
	struct ovs_flow_stats stats;
};

struct dp_meter {
	spinlock_t lock;
	struct callback_head rcu;
	u32 id;
	u16 kbps: 1;
	u16 keep_stats: 1;
	u16 n_bands;
	u32 max_delta_t;
	u64 used;
	struct ovs_flow_stats stats;
	struct dp_meter_band bands[0];
};

struct dp_meter_instance {
	struct callback_head rcu;
	u32 n_meters;
	struct dp_meter *dp_meters[0];
};

struct dp_meter_table {
	struct dp_meter_instance *ti;
	u32 count;
	u32 max_meters_allowed;
};

struct vport_portids {
	struct reciprocal_value rn_ids;
	struct callback_head rcu;
	u32 n_ids;
	u32 ids[0];
};

struct datapath;

struct vport_ops;

struct vport {
	struct net_device___2 *dev;
	netdevice_tracker dev_tracker;
	struct datapath *dp;
	struct vport_portids *upcall_portids;
	u16 port_no;
	struct hlist_node hash_node;
	struct hlist_node dp_hash_node;
	const struct vport_ops *ops;
	struct list_head detach_list;
	struct callback_head rcu;
};

struct dp_stats_percpu;

struct dp_nlsk_pids;

struct datapath {
	struct callback_head rcu;
	struct list_head list_node;
	struct flow_table table;
	struct hlist_head *ports;
	struct dp_stats_percpu *stats_percpu;
	possible_net_t net;
	u32 user_features;
	u32 max_headroom;
	struct dp_meter_table meter_tbl;
	struct dp_nlsk_pids *upcall_portids;
};

struct vport_parms;

struct vport_ops {
	enum ovs_vport_type type;
	struct vport * (*create)(const struct vport_parms *);
	void (*destroy)(struct vport *);
	int (*set_options)(struct vport *, struct nlattr *);
	int (*get_options)(const struct vport *, struct sk_buff___2 *);
	int (*send)(struct sk_buff___2 *);
	struct module___2 *owner;
	struct list_head list;
};

struct vport_parms {
	const char *name;
	enum ovs_vport_type type;
	int desired_ifindex;
	struct nlattr *options;
	struct datapath *dp;
	u16 port_no;
	struct nlattr *upcall_portids;
};

struct dp_stats_percpu {
	u64 n_hit;
	u64 n_missed;
	u64 n_lost;
	u64 n_mask_hit;
	u64 n_cache_hit;
	struct u64_stats_sync syncp;
};

struct dp_nlsk_pids {
	struct callback_head rcu;
	u32 n_pids;
	u32 pids[0];
};

struct ovs_skb_cb {
	struct vport *input_vport;
	u16 mru;
	u16 acts_origlen;
	u32 cutlen;
};

struct dp_upcall_info {
	struct ip_tunnel_info *egress_tun_info;
	const struct nlattr *userdata;
	const struct nlattr *actions;
	int actions_len;
	u32 portid;
	u8 cmd;
	u16 mru;
};

struct deferred_action {
	struct sk_buff___2 *skb;
	const struct nlattr *actions;
	int actions_len;
	struct sw_flow_key pkt_key;
};

struct ovs_frag_data {
	long unsigned int dst;
	struct vport *vport;
	struct ovs_skb_cb cb;
	__be16 inner_protocol;
	u16 network_offset;
	u16 vlan_tci;
	__be16 vlan_proto;
	unsigned int l2_len;
	u8 mac_proto;
	u8 l2_data[30];
};

struct action_fifo {
	int head;
	int tail;
	struct deferred_action fifo[10];
};

struct action_flow_keys {
	struct sw_flow_key key[3];
};

struct ovs_conntrack_info;

enum ovs_vport_cmd {
	OVS_VPORT_CMD_UNSPEC = 0,
	OVS_VPORT_CMD_NEW = 1,
	OVS_VPORT_CMD_DEL = 2,
	OVS_VPORT_CMD_GET = 3,
	OVS_VPORT_CMD_SET = 4,
};

struct ovs_ct_limit_info;

struct ovs_net {
	struct list_head dps;
	struct work_struct dp_notify_work;
	struct delayed_work masks_rebalance;
	struct ovs_ct_limit_info *ct_limit_info;
	bool xt_label;
};

struct dentry___3;

struct super_block___3;

struct module___3;

struct file_system_type___3 {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry___3 * (*mount)(struct file_system_type___3 *, int, const char *, void *);
	void (*kill_sb)(struct super_block___3 *);
	struct module___3 *owner;
	struct file_system_type___3 *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

struct kset___3;

struct kobj_type___3;

struct kernfs_node___3;

struct kobject___3 {
	const char *name;
	struct list_head entry;
	struct kobject___3 *parent;
	struct kset___3 *kset;
	const struct kobj_type___3 *ktype;
	struct kernfs_node___3 *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct module_kobject___3 {
	struct kobject___3 kobj;
	struct module___3 *mod;
	struct kobject___3 *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct mod_tree_node___3 {
	struct module___3 *mod;
	struct latch_tree_node node;
};

struct module_layout___3 {
	void *base;
	unsigned int size;
	unsigned int text_size;
	unsigned int ro_size;
	unsigned int ro_after_init_size;
	struct mod_tree_node___3 mtn;
};

struct module_attribute___3;

struct kernel_param___3;

struct bpf_raw_event_map___3;

struct module___3 {
	enum module_state state;
	struct list_head list;
	char name[56];
	struct module_kobject___3 mkobj;
	struct module_attribute___3 *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject___3 *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param___3 *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool sig_ok;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	struct module_layout___3 core_layout;
	struct module_layout___3 init_layout;
	struct mod_arch_specific arch;
	long unsigned int taints;
	unsigned int num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map___3 *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	int num_static_call_sites;
	struct static_call_site *static_call_sites;
	int num_kunit_suites;
	struct kunit_suite **kunit_suites;
	bool klp;
	bool klp_alive;
	struct klp_modinfo *klp_info;
	unsigned int printk_index_size;
	struct pi_entry **printk_index_start;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
};

struct page___3;

typedef struct page___3 *pgtable_t___3;

struct address_space___3;

struct page_pool___3;

struct mm_struct___3;

struct dev_pagemap___3;

struct page___3 {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space___3 *mapping;
			long unsigned int index;
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool___3 *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			union {
				long unsigned int dma_addr_upper;
				atomic_long_t pp_frag_count;
			};
		};
		struct {
			long unsigned int compound_head;
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			atomic_t compound_pincount;
			unsigned int compound_nr;
		};
		struct {
			long unsigned int _compound_pad_1;
			long unsigned int _compound_pad_2;
			struct list_head deferred_list;
		};
		struct {
			long unsigned int _pt_pad_1;
			pgtable_t___3 pmd_huge_pte;
			long unsigned int _pt_pad_2;
			union {
				struct mm_struct___3 *pt_mm;
				atomic_t pt_frag_refcount;
			};
			spinlock_t ptl;
		};
		struct {
			struct dev_pagemap___3 *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	long unsigned int memcg_data;
};

struct kernel_param_ops___3 {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param___3 *);
	int (*get)(char *, const struct kernel_param___3 *);
	void (*free)(void *);
};

struct file___3;

struct kiocb___3;

struct iov_iter___3;

struct poll_table_struct___3;

struct vm_area_struct___3;

struct inode___3;

struct file_lock___3;

struct pipe_inode_info___3;

struct seq_file___3;

struct file_operations___3 {
	struct module___3 *owner;
	loff_t (*llseek)(struct file___3 *, loff_t, int);
	ssize_t (*read)(struct file___3 *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file___3 *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb___3 *, struct iov_iter___3 *);
	ssize_t (*write_iter)(struct kiocb___3 *, struct iov_iter___3 *);
	int (*iopoll)(struct kiocb___3 *, struct io_comp_batch *, unsigned int);
	int (*iterate)(struct file___3 *, struct dir_context *);
	int (*iterate_shared)(struct file___3 *, struct dir_context *);
	__poll_t (*poll)(struct file___3 *, struct poll_table_struct___3 *);
	long int (*unlocked_ioctl)(struct file___3 *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file___3 *, unsigned int, long unsigned int);
	int (*mmap)(struct file___3 *, struct vm_area_struct___3 *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode___3 *, struct file___3 *);
	int (*flush)(struct file___3 *, fl_owner_t);
	int (*release)(struct inode___3 *, struct file___3 *);
	int (*fsync)(struct file___3 *, loff_t, loff_t, int);
	int (*fasync)(int, struct file___3 *, int);
	int (*lock)(struct file___3 *, int, struct file_lock___3 *);
	ssize_t (*sendpage)(struct file___3 *, struct page___3 *, int, size_t, loff_t *, int);
	long unsigned int (*get_unmapped_area)(struct file___3 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file___3 *, int, struct file_lock___3 *);
	ssize_t (*splice_write)(struct pipe_inode_info___3 *, struct file___3 *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file___3 *, loff_t *, struct pipe_inode_info___3 *, size_t, unsigned int);
	int (*setlease)(struct file___3 *, long int, struct file_lock___3 **, void **);
	long int (*fallocate)(struct file___3 *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file___3 *, struct file___3 *);
	ssize_t (*copy_file_range)(struct file___3 *, loff_t, struct file___3 *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file___3 *, loff_t, struct file___3 *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file___3 *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

struct static_call_mod___3 {
	struct static_call_mod___3 *next;
	struct module___3 *mod;
	struct static_call_site *sites;
};

struct static_call_key___3 {
	void *func;
	union {
		long unsigned int type;
		struct static_call_mod___3 *mods;
		struct static_call_site *sites;
	};
};

struct page_frag___3 {
	struct page___3 *page;
	__u32 offset;
	__u32 size;
};

struct nsproxy___3;

struct signal_struct___3;

struct bio_list___3;

struct backing_dev_info___3;

struct css_set___3;

struct mem_cgroup___3;

struct vm_struct___3;

struct task_struct___3 {
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct___3 *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	const struct sched_class *sched_class;
	struct rb_node core_node;
	long unsigned int core_cookie;
	unsigned int core_occupation;
	struct task_group *sched_task_group;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_statistics stats;
	struct hlist_head preempt_notifiers;
	unsigned int btrace_seq;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct___3 *mm;
	struct mm_struct___3 *active_mm;
	struct task_rss_stat rss_stat;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	unsigned int sched_psi_wake_requeue: 1;
	int: 28;
	unsigned int sched_remote_wakeup: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int in_user_fault: 1;
	unsigned int in_lru_fault: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_page_owner: 1;
	unsigned int in_eventfd: 1;
	unsigned int pasid_activated: 1;
	unsigned int reported_split_lock: 1;
	unsigned int in_thrashing: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct___3 *real_parent;
	struct task_struct___3 *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct___3 *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_group;
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	struct vtime vtime;
	atomic_t tick_dep_mask;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	struct posix_cputimers_work posix_cputimers_work;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy___3 *nsproxy;
	struct signal_struct___3 *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct audit_context *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct___3 *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	void *journal_info;
	struct bio_list___3 *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct backing_dev_info___3 *backing_dev_info;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	unsigned int psi_flags;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
	struct css_set___3 *cgroups;
	struct list_head cg_list;
	u32 closid;
	u32 rmid;
	struct robust_list_head *robust_list;
	struct compat_robust_list_head *compat_robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	struct perf_event_context *perf_event_ctxp[2];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	long unsigned int preempt_disable_ip;
	struct mempolicy *mempolicy;
	short int il_prev;
	short int pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	long unsigned int numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct numa_group *numa_group;
	long unsigned int *numa_faults;
	long unsigned int total_numa_faults;
	long unsigned int numa_faults_locality[3];
	long unsigned int numa_pages_migrated;
	struct rseq *rseq;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	struct tlbflush_unmap_batch tlb_ubc;
	union {
		refcount_t rcu_users;
		struct callback_head rcu;
	};
	struct pipe_inode_info___3 *splice_pipe;
	struct page_frag___3 task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	int latency_record_count;
	struct latency_record latency_record[32];
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	struct kunit *kunit_test;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace_recursion;
	struct mem_cgroup___3 *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup___3 *active_memcg;
	struct request_queue *throttle_queue;
	struct uprobe_task *utask;
	unsigned int sequential_io;
	unsigned int sequential_io_avg;
	struct kmap_ctrl kmap_ctrl;
	int pagefault_disabled;
	struct task_struct___3 *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct___3 *stack_vm_area;
	refcount_t stack_refcount;
	int patch_state;
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	void *mce_vaddr;
	__u64 mce_kflags;
	u64 mce_addr;
	__u64 mce_ripv: 1;
	__u64 mce_whole_page: 1;
	__u64 __mce_reserved: 62;
	struct callback_head mce_kill_me;
	int mce_count;
	struct llist_head kretprobe_instances;
	struct llist_head rethooks;
	struct callback_head l1d_flush_kill;
	union rv_task_monitor rv[1];
	struct thread_struct thread;
};

struct mm_struct___3 {
	struct {
		struct maple_tree mm_mt;
		long unsigned int (*get_unmapped_area)(struct file___3 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int mmap_compat_base;
		long unsigned int mmap_compat_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		atomic_t mm_count;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[48];
		struct mm_rss_stat rss_stat;
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct___3 *owner;
		struct user_namespace *user_ns;
		struct file___3 *exe_file;
		struct mmu_notifier_subscriptions *notifier_subscriptions;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		atomic_t tlb_flush_batched;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		u32 pasid;
		long unsigned int ksm_merging_pages;
		long unsigned int ksm_rmap_items;
		struct {
			struct list_head list;
			long unsigned int bitmap;
			struct mem_cgroup___3 *memcg;
		} lru_gen;
	};
	long unsigned int cpu_bitmap[0];
};

struct vm_operations_struct___3;

struct vm_area_struct___3 {
	long unsigned int vm_start;
	long unsigned int vm_end;
	struct mm_struct___3 *vm_mm;
	pgprot_t vm_page_prot;
	long unsigned int vm_flags;
	union {
		struct {
			struct rb_node rb;
			long unsigned int rb_subtree_last;
		} shared;
		struct anon_vma_name *anon_name;
	};
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct___3 *vm_ops;
	long unsigned int vm_pgoff;
	struct file___3 *vm_file;
	void *vm_private_data;
	atomic_long_t swap_readahead_info;
	struct mempolicy *vm_policy;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

struct bin_attribute___3;

struct attribute_group___3 {
	const char *name;
	umode_t (*is_visible)(struct kobject___3 *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject___3 *, struct bin_attribute___3 *, int);
	struct attribute **attrs;
	struct bin_attribute___3 **bin_attrs;
};

struct tracepoint___3 {
	const char *name;
	struct static_key key;
	struct static_call_key___3 *static_call_key;
	void *static_call_tramp;
	void *iterator;
	int (*regfunc)();
	void (*unregfunc)();
	struct tracepoint_func *funcs;
};

struct bpf_raw_event_map___3 {
	struct tracepoint___3 *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	long: 64;
};

struct seq_operations___3 {
	void * (*start)(struct seq_file___3 *, loff_t *);
	void (*stop)(struct seq_file___3 *, void *);
	void * (*next)(struct seq_file___3 *, void *, loff_t *);
	int (*show)(struct seq_file___3 *, void *);
};

struct address_space_operations___3;

struct address_space___3 {
	struct inode___3 *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	struct rw_semaphore i_mmap_rwsem;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations___3 *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t private_lock;
	struct list_head private_list;
	void *private_data;
};

struct device___3;

struct page_pool_params___3 {
	unsigned int flags;
	unsigned int order;
	unsigned int pool_size;
	int nid;
	struct device___3 *dev;
	enum dma_data_direction dma_dir;
	unsigned int max_len;
	unsigned int offset;
	void (*init_callback)(struct page___3 *, void *);
	void *init_arg;
};

struct pp_alloc_cache___3 {
	u32 count;
	struct page___3 *cache[128];
};

struct page_pool___3 {
	struct page_pool_params___3 p;
	struct delayed_work release_dw;
	void (*disconnect)(void *);
	long unsigned int defer_start;
	long unsigned int defer_warn;
	u32 pages_state_hold_cnt;
	unsigned int frag_offset;
	struct page___3 *frag_page;
	long int frag_users;
	u32 xdp_mem_id;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct pp_alloc_cache___3 alloc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct ptr_ring ring;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct dev_pagemap_ops___3;

struct dev_pagemap___3 {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops___3 *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct range ranges[0];
	};
};

struct folio___3 {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space___3 *mapping;
			long unsigned int index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page___3 page;
	};
	long unsigned int _flags_1;
	long unsigned int __head;
	unsigned char _folio_dtor;
	unsigned char _folio_order;
	atomic_t _total_mapcount;
	atomic_t _pincount;
	unsigned int _folio_nr_pages;
};

struct vfsmount___3;

struct path___3 {
	struct vfsmount___3 *mnt;
	struct dentry___3 *dentry;
};

struct file___3 {
	union {
		struct llist_node f_llist;
		struct callback_head f_rcuhead;
		unsigned int f_iocb_flags;
	};
	struct path___3 f_path;
	struct inode___3 *f_inode;
	const struct file_operations___3 *f_op;
	spinlock_t f_lock;
	atomic_long_t f_count;
	unsigned int f_flags;
	fmode_t f_mode;
	struct mutex f_pos_lock;
	loff_t f_pos;
	struct fown_struct f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	u64 f_version;
	void *f_security;
	void *private_data;
	struct hlist_head *f_ep;
	struct address_space___3 *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};

struct vm_fault___3;

struct vm_operations_struct___3 {
	void (*open)(struct vm_area_struct___3 *);
	void (*close)(struct vm_area_struct___3 *);
	int (*may_split)(struct vm_area_struct___3 *, long unsigned int);
	int (*mremap)(struct vm_area_struct___3 *);
	int (*mprotect)(struct vm_area_struct___3 *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault___3 *);
	vm_fault_t (*huge_fault)(struct vm_fault___3 *, enum page_entry_size);
	vm_fault_t (*map_pages)(struct vm_fault___3 *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct___3 *);
	vm_fault_t (*page_mkwrite)(struct vm_fault___3 *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault___3 *);
	int (*access)(struct vm_area_struct___3 *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct___3 *);
	int (*set_policy)(struct vm_area_struct___3 *, struct mempolicy *);
	struct mempolicy * (*get_policy)(struct vm_area_struct___3 *, long unsigned int);
	struct page___3 * (*find_special_page)(struct vm_area_struct___3 *, long unsigned int);
};

struct mem_cgroup___3 {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct page_counter memory;
	union {
		struct page_counter swap;
		struct page_counter memsw;
	};
	struct page_counter kmem;
	struct page_counter tcpmem;
	struct work_struct high_work;
	long unsigned int zswap_max;
	long unsigned int soft_limit;
	struct vmpressure vmpressure;
	bool oom_group;
	bool oom_lock;
	int under_oom;
	int swappiness;
	int oom_kill_disable;
	struct cgroup_file events_file;
	struct cgroup_file events_local_file;
	struct cgroup_file swap_events_file;
	struct mutex thresholds_lock;
	struct mem_cgroup_thresholds thresholds;
	struct mem_cgroup_thresholds memsw_thresholds;
	struct list_head oom_notify;
	long unsigned int move_charge_at_immigrate;
	spinlock_t move_lock;
	long unsigned int move_lock_flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct memcg_vmstats *vmstats;
	atomic_long_t memory_events[9];
	atomic_long_t memory_events_local[9];
	long unsigned int socket_pressure;
	bool tcpmem_active;
	int tcpmem_pressure;
	int kmemcg_id;
	struct obj_cgroup *objcg;
	struct list_head objcg_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	atomic_t moving_account;
	struct task_struct___3 *move_lock_task;
	struct memcg_vmstats_percpu *vmstats_percpu;
	struct list_head cgwb_list;
	struct wb_domain cgwb_domain;
	struct memcg_cgwb_frn cgwb_frn[4];
	struct list_head event_list;
	spinlock_t event_list_lock;
	struct deferred_split deferred_split_queue;
	struct lru_gen_mm_list mm_list;
	struct mem_cgroup_per_node *nodeinfo[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct vm_fault___3 {
	const struct {
		struct vm_area_struct___3 *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page___3 *cow_page;
	struct page___3 *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t___3 prealloc_pte;
};

struct lruvec___3;

struct lru_gen_mm_walk___3 {
	struct lruvec___3 *lruvec;
	long unsigned int max_seq;
	long unsigned int next_addr;
	int nr_pages[40];
	int mm_stats[6];
	int batched;
	bool can_swap;
	bool force_scan;
};

struct pglist_data___3;

struct lruvec___3 {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
	struct lru_gen_struct lrugen;
	struct lru_gen_mm_state mm_state;
	struct pglist_data___3 *pgdat;
};

struct zone___3 {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long int lowmem_reserve[5];
	int node;
	struct pglist_data___3 *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high;
	int pageset_batch;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	long unsigned int present_early_pages;
	long unsigned int cma_pages;
	const char *name;
	long unsigned int nr_isolate_pageblock;
	seqlock_t span_seqlock;
	int initialized;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct free_area free_area[11];
	long unsigned int flags;
	spinlock_t lock;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int percpu_drift_mark;
	long unsigned int compact_cached_free_pfn;
	long unsigned int compact_cached_migrate_pfn[2];
	long unsigned int compact_init_migrate_pfn;
	long unsigned int compact_init_free_pfn;
	unsigned int compact_considered;
	unsigned int compact_defer_shift;
	int compact_order_failed;
	bool compact_blockskip_flush;
	bool contiguous;
	short: 16;
	struct cacheline_padding _pad3_;
	atomic_long_t vm_stat[11];
	atomic_long_t vm_numa_event[6];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct zoneref___3 {
	struct zone___3 *zone;
	int zone_idx;
};

struct zonelist___3 {
	struct zoneref___3 _zonerefs[5121];
};

struct pglist_data___3 {
	struct zone___3 node_zones[5];
	struct zonelist___3 node_zonelists[2];
	int nr_zones;
	spinlock_t node_size_lock;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct mutex kswapd_lock;
	struct task_struct___3 *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct___3 *kcompactd;
	bool proactive_compact_trigger;
	long unsigned int totalreserve_pages;
	long unsigned int min_unmapped_pages;
	long unsigned int min_slab_pages;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct deferred_split deferred_split_queue;
	unsigned int nbp_rl_start;
	long unsigned int nbp_rl_nr_cand;
	unsigned int nbp_threshold;
	unsigned int nbp_th_start;
	long unsigned int nbp_th_nr_cand;
	struct lruvec___3 __lruvec;
	long unsigned int flags;
	struct lru_gen_mm_walk___3 mm_walk;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[43];
	struct memory_tier *memtier;
	long: 64;
	long: 64;
	long: 64;
};

struct core_state___3;

struct signal_struct___3 {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct___3 *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct___3 *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state___3 *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	int posix_timer_id;
	struct list_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid *pids[4];
	atomic_t tick_dep_mask;
	struct pid *tty_old_pgrp;
	int leader;
	struct tty_struct___2 *tty;
	struct autogroup *autogroup;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	unsigned int audit_tty;
	struct tty_audit_buf *tty_audit_buf;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct___3 *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct net___3;

struct nsproxy___3 {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net___3 *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct bio___3;

struct bio_list___3 {
	struct bio___3 *head;
	struct bio___3 *tail;
};

struct bdi_writeback___3 {
	struct backing_dev_info___3 *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	long unsigned int dirty_sleep;
	struct list_head bdi_node;
	struct percpu_ref refcnt;
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css;
	struct cgroup_subsys_state *blkcg_css;
	struct list_head memcg_node;
	struct list_head blkcg_node;
	struct list_head b_attached;
	struct list_head offline_node;
	union {
		struct work_struct release_work;
		struct callback_head rcu;
	};
};

struct backing_dev_info___3 {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	struct bdi_writeback___3 wb;
	struct list_head wb_list;
	struct xarray cgwb_tree;
	struct mutex cgwb_release_mutex;
	struct rw_semaphore wb_switch_rwsem;
	wait_queue_head_t wb_waitq;
	struct device___3 *dev;
	char dev_name[64];
	struct device___3 *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry___3 *debug_dir;
};

struct cgroup___3;

struct css_set___3 {
	struct cgroup_subsys_state *subsys[13];
	refcount_t refcount;
	struct css_set___3 *dom_cset;
	struct cgroup___3 *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[13];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_src_preload_node;
	struct list_head mg_dst_preload_node;
	struct list_head mg_node;
	struct cgroup___3 *mg_src_cgrp;
	struct cgroup___3 *mg_dst_cgrp;
	struct css_set___3 *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
};

struct fasync_struct___3;

struct pipe_buffer___3;

struct pipe_inode_info___3 {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	bool note_loss;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	struct page___3 *tmp_page;
	struct fasync_struct___3 *fasync_readers;
	struct fasync_struct___3 *fasync_writers;
	struct pipe_buffer___3 *bufs;
	struct user_struct *user;
	struct watch_queue *watch_queue;
};

struct vm_struct___3 {
	struct vm_struct___3 *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page___3 **pages;
	unsigned int page_order;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

struct kernfs_elem_symlink___3 {
	struct kernfs_node___3 *target_kn;
};

struct kernfs_ops___3;

struct kernfs_elem_attr___3 {
	const struct kernfs_ops___3 *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node___3 *notify_next;
};

struct kernfs_node___3 {
	atomic_t count;
	atomic_t active;
	struct kernfs_node___3 *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink___3 symlink;
		struct kernfs_elem_attr___3 attr;
	};
	void *priv;
	u64 id;
	short unsigned int flags;
	umode_t mode;
	struct kernfs_iattrs *iattr;
};

struct kernfs_open_file___3;

struct kernfs_ops___3 {
	int (*open)(struct kernfs_open_file___3 *);
	void (*release)(struct kernfs_open_file___3 *);
	int (*seq_show)(struct seq_file___3 *, void *);
	void * (*seq_start)(struct seq_file___3 *, loff_t *);
	void * (*seq_next)(struct seq_file___3 *, void *, loff_t *);
	void (*seq_stop)(struct seq_file___3 *, void *);
	ssize_t (*read)(struct kernfs_open_file___3 *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file___3 *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file___3 *, struct poll_table_struct___3 *);
	int (*mmap)(struct kernfs_open_file___3 *, struct vm_area_struct___3 *);
};

struct seq_file___3 {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations___3 *op;
	int poll_event;
	const struct file___3 *file;
	void *private;
};

struct kernfs_open_file___3 {
	struct kernfs_node___3 *kn;
	struct file___3 *file;
	struct seq_file___3 *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct___3 *vm_ops;
};

typedef void (*poll_queue_proc___3)(struct file___3 *, wait_queue_head_t *, struct poll_table_struct___3 *);

struct poll_table_struct___3 {
	poll_queue_proc___3 _qproc;
	__poll_t _key;
};

struct sock___3;

struct kobj_ns_type_operations___3 {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock___3 *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

struct sk_buff___3;

struct sk_buff_list___3 {
	struct sk_buff___3 *next;
	struct sk_buff___3 *prev;
};

struct sk_buff_head___3 {
	union {
		struct {
			struct sk_buff___3 *next;
			struct sk_buff___3 *prev;
		};
		struct sk_buff_list___3 list;
	};
	__u32 qlen;
	spinlock_t lock;
};

struct socket___3;

struct net_device___3;

struct sock___3 {
	struct sock_common __sk_common;
	struct dst_entry *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	socket_lock_t sk_lock;
	atomic_t sk_drops;
	int sk_rcvlowat;
	struct sk_buff_head___3 sk_error_queue;
	struct sk_buff_head___3 sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	int sk_forward_alloc;
	u32 sk_reserved_mem;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	int sk_rcvbuf;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	struct xfrm_policy *sk_policy[2];
	struct dst_entry *sk_dst_cache;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head___3 sk_write_queue;
	__s32 sk_peek_off;
	int sk_write_pending;
	__u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	long int sk_sndtimeo;
	struct timer_list sk_timer;
	__u32 sk_priority;
	__u32 sk_mark;
	long unsigned int sk_pacing_rate;
	long unsigned int sk_max_pacing_rate;
	struct page_frag___3 sk_frag;
	netdev_features_t sk_route_caps;
	int sk_gso_type;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	__u32 sk_txhash;
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_userlocks: 4;
	u8 sk_pacing_shift;
	u16 sk_type;
	u16 sk_protocol;
	u16 sk_gso_max_segs;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	u8 sk_txrehash;
	u8 sk_prefer_busy_poll;
	u16 sk_busy_poll_budget;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid *sk_peer_pid;
	const struct cred *sk_peer_cred;
	long int sk_rcvtimeo;
	ktime_t sk_stamp;
	u16 sk_tsflags;
	u8 sk_shutdown;
	atomic_t sk_tskey;
	atomic_t sk_zckey;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	struct socket___3 *sk_socket;
	void *sk_user_data;
	void *sk_security;
	struct sock_cgroup_data sk_cgrp_data;
	struct mem_cgroup___3 *sk_memcg;
	void (*sk_state_change)(struct sock___3 *);
	void (*sk_data_ready)(struct sock___3 *);
	void (*sk_write_space)(struct sock___3 *);
	void (*sk_error_report)(struct sock___3 *);
	int (*sk_backlog_rcv)(struct sock___3 *, struct sk_buff___3 *);
	struct sk_buff___3 * (*sk_validate_xmit_skb)(struct sock___3 *, struct net_device___3 *, struct sk_buff___3 *);
	void (*sk_destruct)(struct sock___3 *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
	struct hlist_node sk_bind2_node;
};

struct bin_attribute___3 {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space___3 * (*f_mapping)();
	ssize_t (*read)(struct file___3 *, struct kobject___3 *, struct bin_attribute___3 *, char *, loff_t, size_t);
	ssize_t (*write)(struct file___3 *, struct kobject___3 *, struct bin_attribute___3 *, char *, loff_t, size_t);
	int (*mmap)(struct file___3 *, struct kobject___3 *, struct bin_attribute___3 *, struct vm_area_struct___3 *);
};

struct sysfs_ops___3 {
	ssize_t (*show)(struct kobject___3 *, struct attribute *, char *);
	ssize_t (*store)(struct kobject___3 *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops___3;

struct kset___3 {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject___3 kobj;
	const struct kset_uevent_ops___3 *uevent_ops;
};

struct kobj_type___3 {
	void (*release)(struct kobject___3 *);
	const struct sysfs_ops___3 *sysfs_ops;
	const struct attribute_group___3 **default_groups;
	const struct kobj_ns_type_operations___3 * (*child_ns_type)(struct kobject___3 *);
	const void * (*namespace)(struct kobject___3 *);
	void (*get_ownership)(struct kobject___3 *, kuid_t *, kgid_t *);
};

struct kset_uevent_ops___3 {
	int (* const filter)(struct kobject___3 *);
	const char * (* const name)(struct kobject___3 *);
	int (* const uevent)(struct kobject___3 *, struct kobj_uevent_env *);
};

struct kparam_array___3;

struct kernel_param___3 {
	const char *name;
	struct module___3 *mod;
	const struct kernel_param_ops___3 *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array___3 *arr;
	};
};

struct kparam_array___3 {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops___3 *ops;
	void *elem;
};

struct module_attribute___3 {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute___3 *, struct module_kobject___3 *, char *);
	ssize_t (*store)(struct module_attribute___3 *, struct module_kobject___3 *, const char *, size_t);
	void (*setup)(struct module___3 *, const char *);
	int (*test)(struct module___3 *);
	void (*free)(struct module___3 *);
};

struct dentry_operations___3;

struct dentry___3 {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry___3 *d_parent;
	struct qstr d_name;
	struct inode___3 *d_inode;
	unsigned char d_iname[32];
	struct lockref d_lockref;
	const struct dentry_operations___3 *d_op;
	struct super_block___3 *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct list_head d_child;
	struct list_head d_subdirs;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

struct inode_operations___3;

struct inode___3 {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations___3 *i_op;
	struct super_block___3 *i_sb;
	struct address_space___3 *i_mapping;
	void *i_security;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback___3 *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations___3 *i_fop;
		void (*free_inode)(struct inode___3 *);
	};
	struct file_lock_context *i_flctx;
	struct address_space___3 i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info___3 *i_pipe;
		struct cdev___2 *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_info *i_crypt_info;
	struct fsverity_info *i_verity_info;
	void *i_private;
};

struct dentry_operations___3 {
	int (*d_revalidate)(struct dentry___3 *, unsigned int);
	int (*d_weak_revalidate)(struct dentry___3 *, unsigned int);
	int (*d_hash)(const struct dentry___3 *, struct qstr *);
	int (*d_compare)(const struct dentry___3 *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry___3 *);
	int (*d_init)(struct dentry___3 *);
	void (*d_release)(struct dentry___3 *);
	void (*d_prune)(struct dentry___3 *);
	void (*d_iput)(struct dentry___3 *, struct inode___3 *);
	char * (*d_dname)(struct dentry___3 *, char *, int);
	struct vfsmount___3 * (*d_automount)(struct path___3 *);
	int (*d_manage)(const struct path___3 *, bool);
	struct dentry___3 * (*d_real)(struct dentry___3 *, const struct inode___3 *);
	long: 64;
	long: 64;
	long: 64;
};

struct quota_format_type___3;

struct mem_dqinfo___3 {
	struct quota_format_type___3 *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};

struct quota_format_ops___3;

struct quota_info___3 {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode___3 *files[3];
	struct mem_dqinfo___3 info[3];
	const struct quota_format_ops___3 *ops[3];
};

struct rcuwait___3 {
	struct task_struct___3 *task;
};

struct percpu_rw_semaphore___3 {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait___3 writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers___3 {
	int frozen;
	wait_queue_head_t wait_unfrozen;
	struct percpu_rw_semaphore___3 rw_sem[3];
};

struct shrink_control___3;

struct shrinker___3 {
	long unsigned int (*count_objects)(struct shrinker___3 *, struct shrink_control___3 *);
	long unsigned int (*scan_objects)(struct shrinker___3 *, struct shrink_control___3 *);
	long int batch;
	int seeks;
	unsigned int flags;
	struct list_head list;
	int id;
	atomic_long_t *nr_deferred;
};

struct super_operations___3;

struct dquot_operations___3;

struct quotactl_ops___3;

struct block_device___3;

struct super_block___3 {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type___3 *s_type;
	const struct super_operations___3 *s_op;
	const struct dquot_operations___3 *dq_op;
	const struct quotactl_ops___3 *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry___3 *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	void *s_security;
	const struct xattr_handler **s_xattr;
	const struct fscrypt_operations *s_cop;
	struct fscrypt_keyring *s_master_keys;
	const struct fsverity_operations *s_vop;
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device___3 *s_bdev;
	struct backing_dev_info___3 *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info___3 s_dquot;
	struct sb_writers___3 s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	__u32 s_fsnotify_mask;
	struct fsnotify_mark_connector *s_fsnotify_marks;
	char s_id[32];
	uuid_t s_uuid;
	unsigned int s_max_links;
	fmode_t s_mode;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations___3 *s_d_op;
	struct shrinker___3 s_shrink;
	atomic_long_t s_remove_count;
	atomic_long_t s_fsnotify_connectors;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 64;
	long: 64;
};

struct vfsmount___3 {
	struct dentry___3 *mnt_root;
	struct super_block___3 *mnt_sb;
	int mnt_flags;
	struct user_namespace *mnt_userns;
};

struct shrink_control___3 {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup___3 *memcg;
};

struct cgroup___3 {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	struct kernfs_node___3 *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	struct cgroup_file psi_files[4];
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[13];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[13];
	struct cgroup___3 *dom_cgrp;
	struct cgroup___3 *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group *psi;
	struct cgroup_bpf bpf;
	atomic_t congestion_count;
	struct cgroup_freezer_state freezer;
	struct cgroup___3 *ancestors[0];
};

struct core_thread___3 {
	struct task_struct___3 *task;
	struct core_thread___3 *next;
};

struct core_state___3 {
	atomic_t nr_threads;
	struct core_thread___3 dumper;
	struct completion startup;
};

struct kiocb___3 {
	struct file___3 *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb___3 *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	struct wait_page_queue *ki_waitq;
};

struct iattr___3 {
	unsigned int ia_valid;
	umode_t ia_mode;
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file___3 *ia_file;
};

struct dquot___3 {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block___3 *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};

struct quota_format_type___3 {
	int qf_fmt_id;
	const struct quota_format_ops___3 *qf_ops;
	struct module___3 *qf_owner;
	struct quota_format_type___3 *qf_next;
};

struct quota_format_ops___3 {
	int (*check_quota_file)(struct super_block___3 *, int);
	int (*read_file_info)(struct super_block___3 *, int);
	int (*write_file_info)(struct super_block___3 *, int);
	int (*free_file_info)(struct super_block___3 *, int);
	int (*read_dqblk)(struct dquot___3 *);
	int (*commit_dqblk)(struct dquot___3 *);
	int (*release_dqblk)(struct dquot___3 *);
	int (*get_next_id)(struct super_block___3 *, struct kqid *);
};

struct dquot_operations___3 {
	int (*write_dquot)(struct dquot___3 *);
	struct dquot___3 * (*alloc_dquot)(struct super_block___3 *, int);
	void (*destroy_dquot)(struct dquot___3 *);
	int (*acquire_dquot)(struct dquot___3 *);
	int (*release_dquot)(struct dquot___3 *);
	int (*mark_dirty)(struct dquot___3 *);
	int (*write_info)(struct super_block___3 *, int);
	qsize_t * (*get_reserved_space)(struct inode___3 *);
	int (*get_projid)(struct inode___3 *, kprojid_t *);
	int (*get_inode_usage)(struct inode___3 *, qsize_t *);
	int (*get_next_id)(struct super_block___3 *, struct kqid *);
};

struct quotactl_ops___3 {
	int (*quota_on)(struct super_block___3 *, int, int, const struct path___3 *);
	int (*quota_off)(struct super_block___3 *, int);
	int (*quota_enable)(struct super_block___3 *, unsigned int);
	int (*quota_disable)(struct super_block___3 *, unsigned int);
	int (*quota_sync)(struct super_block___3 *, int);
	int (*set_info)(struct super_block___3 *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block___3 *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block___3 *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block___3 *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block___3 *, struct qc_state *);
	int (*rm_xquota)(struct super_block___3 *, unsigned int);
};

struct writeback_control___3;

struct address_space_operations___3 {
	int (*writepage)(struct page___3 *, struct writeback_control___3 *);
	int (*read_folio)(struct file___3 *, struct folio___3 *);
	int (*writepages)(struct address_space___3 *, struct writeback_control___3 *);
	bool (*dirty_folio)(struct address_space___3 *, struct folio___3 *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file___3 *, struct address_space___3 *, loff_t, unsigned int, struct page___3 **, void **);
	int (*write_end)(struct file___3 *, struct address_space___3 *, loff_t, unsigned int, unsigned int, struct page___3 *, void *);
	sector_t (*bmap)(struct address_space___3 *, sector_t);
	void (*invalidate_folio)(struct folio___3 *, size_t, size_t);
	bool (*release_folio)(struct folio___3 *, gfp_t);
	void (*free_folio)(struct folio___3 *);
	ssize_t (*direct_IO)(struct kiocb___3 *, struct iov_iter___3 *);
	int (*migrate_folio)(struct address_space___3 *, struct folio___3 *, struct folio___3 *, enum migrate_mode);
	int (*launder_folio)(struct folio___3 *);
	bool (*is_partially_uptodate)(struct folio___3 *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio___3 *, bool *, bool *);
	int (*error_remove_page)(struct address_space___3 *, struct page___3 *);
	int (*swap_activate)(struct swap_info_struct *, struct file___3 *, sector_t *);
	void (*swap_deactivate)(struct file___3 *);
	int (*swap_rw)(struct kiocb___3 *, struct iov_iter___3 *);
};

struct writeback_control___3 {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_fscache_wb: 1;
	unsigned int no_cgroup_owner: 1;
	unsigned int punt_to_cgroup: 1;
	struct swap_iocb **swap_plug;
	struct bdi_writeback___3 *wb;
	struct inode___3 *inode;
	int wb_id;
	int wb_lcand_id;
	int wb_tcand_id;
	size_t wb_bytes;
	size_t wb_lcand_bytes;
	size_t wb_tcand_bytes;
};

struct bio_vec___3;

struct iov_iter___3 {
	u8 iter_type;
	bool nofault;
	bool data_source;
	bool user_backed;
	union {
		size_t iov_offset;
		int last_offset;
	};
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec___3 *bvec;
		struct xarray *xarray;
		struct pipe_inode_info___3 *pipe;
		void *ubuf;
	};
	union {
		long unsigned int nr_segs;
		struct {
			unsigned int head;
			unsigned int start_head;
		};
		loff_t xarray_start;
	};
};

struct inode_operations___3 {
	struct dentry___3 * (*lookup)(struct inode___3 *, struct dentry___3 *, unsigned int);
	const char * (*get_link)(struct dentry___3 *, struct inode___3 *, struct delayed_call *);
	int (*permission)(struct user_namespace *, struct inode___3 *, int);
	struct posix_acl * (*get_acl)(struct inode___3 *, int, bool);
	int (*readlink)(struct dentry___3 *, char *, int);
	int (*create)(struct user_namespace *, struct inode___3 *, struct dentry___3 *, umode_t, bool);
	int (*link)(struct dentry___3 *, struct inode___3 *, struct dentry___3 *);
	int (*unlink)(struct inode___3 *, struct dentry___3 *);
	int (*symlink)(struct user_namespace *, struct inode___3 *, struct dentry___3 *, const char *);
	int (*mkdir)(struct user_namespace *, struct inode___3 *, struct dentry___3 *, umode_t);
	int (*rmdir)(struct inode___3 *, struct dentry___3 *);
	int (*mknod)(struct user_namespace *, struct inode___3 *, struct dentry___3 *, umode_t, dev_t);
	int (*rename)(struct user_namespace *, struct inode___3 *, struct dentry___3 *, struct inode___3 *, struct dentry___3 *, unsigned int);
	int (*setattr)(struct user_namespace *, struct dentry___3 *, struct iattr___3 *);
	int (*getattr)(struct user_namespace *, const struct path___3 *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry___3 *, char *, size_t);
	int (*fiemap)(struct inode___3 *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode___3 *, struct timespec64 *, int);
	int (*atomic_open)(struct inode___3 *, struct dentry___3 *, struct file___3 *, unsigned int, umode_t);
	int (*tmpfile)(struct user_namespace *, struct inode___3 *, struct file___3 *, umode_t);
	int (*set_acl)(struct user_namespace *, struct inode___3 *, struct posix_acl *, int);
	int (*fileattr_set)(struct user_namespace *, struct dentry___3 *, struct fileattr *);
	int (*fileattr_get)(struct dentry___3 *, struct fileattr *);
	long: 64;
};

struct file_lock_operations___3 {
	void (*fl_copy_lock)(struct file_lock___3 *, struct file_lock___3 *);
	void (*fl_release_private)(struct file_lock___3 *);
};

struct lock_manager_operations___3;

struct file_lock___3 {
	struct file_lock___3 *fl_blocker;
	struct list_head fl_list;
	struct hlist_node fl_link;
	struct list_head fl_blocked_requests;
	struct list_head fl_blocked_member;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	unsigned int fl_pid;
	int fl_link_cpu;
	wait_queue_head_t fl_wait;
	struct file___3 *fl_file;
	loff_t fl_start;
	loff_t fl_end;
	struct fasync_struct___3 *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct file_lock_operations___3 *fl_ops;
	const struct lock_manager_operations___3 *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
	} fl_u;
};

struct lock_manager_operations___3 {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock___3 *);
	int (*lm_grant)(struct file_lock___3 *, int);
	bool (*lm_break)(struct file_lock___3 *);
	int (*lm_change)(struct file_lock___3 *, int, struct list_head *);
	void (*lm_setup)(struct file_lock___3 *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lock___3 *);
	bool (*lm_lock_expirable)(struct file_lock___3 *);
	void (*lm_expire_lock)();
};

struct fasync_struct___3 {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct___3 *fa_next;
	struct file___3 *fa_file;
	struct callback_head fa_rcu;
};

struct super_operations___3 {
	struct inode___3 * (*alloc_inode)(struct super_block___3 *);
	void (*destroy_inode)(struct inode___3 *);
	void (*free_inode)(struct inode___3 *);
	void (*dirty_inode)(struct inode___3 *, int);
	int (*write_inode)(struct inode___3 *, struct writeback_control___3 *);
	int (*drop_inode)(struct inode___3 *);
	void (*evict_inode)(struct inode___3 *);
	void (*put_super)(struct super_block___3 *);
	int (*sync_fs)(struct super_block___3 *, int);
	int (*freeze_super)(struct super_block___3 *);
	int (*freeze_fs)(struct super_block___3 *);
	int (*thaw_super)(struct super_block___3 *);
	int (*unfreeze_fs)(struct super_block___3 *);
	int (*statfs)(struct dentry___3 *, struct kstatfs *);
	int (*remount_fs)(struct super_block___3 *, int *, char *);
	void (*umount_begin)(struct super_block___3 *);
	int (*show_options)(struct seq_file___3 *, struct dentry___3 *);
	int (*show_devname)(struct seq_file___3 *, struct dentry___3 *);
	int (*show_path)(struct seq_file___3 *, struct dentry___3 *);
	int (*show_stats)(struct seq_file___3 *, struct dentry___3 *);
	ssize_t (*quota_read)(struct super_block___3 *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block___3 *, int, const char *, size_t, loff_t);
	struct dquot___3 ** (*get_dquots)(struct inode___3 *);
	long int (*nr_cached_objects)(struct super_block___3 *, struct shrink_control___3 *);
	long int (*free_cached_objects)(struct super_block___3 *, struct shrink_control___3 *);
};

struct wakeup_source___3;

struct dev_pm_info___3 {
	pm_message_t power_state;
	unsigned int can_wakeup: 1;
	unsigned int async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	struct list_head entry;
	struct completion completion;
	struct wakeup_source___3 *wakeup;
	bool wakeup_path: 1;
	bool syscore: 1;
	bool no_pm_callbacks: 1;
	unsigned int must_resume: 1;
	unsigned int may_skip_resume: 1;
	struct hrtimer suspend_timer;
	u64 timer_expires;
	struct work_struct work;
	wait_queue_head_t wait_queue;
	struct wake_irq *wakeirq;
	atomic_t usage_count;
	atomic_t child_count;
	unsigned int disable_depth: 3;
	unsigned int idle_notification: 1;
	unsigned int request_pending: 1;
	unsigned int deferred_resume: 1;
	unsigned int needs_force_resume: 1;
	unsigned int runtime_auto: 1;
	bool ignore_children: 1;
	unsigned int no_callbacks: 1;
	unsigned int irq_safe: 1;
	unsigned int use_autosuspend: 1;
	unsigned int timer_autosuspends: 1;
	unsigned int memalloc_noio: 1;
	unsigned int links_count;
	enum rpm_request request;
	enum rpm_status runtime_status;
	enum rpm_status last_status;
	int runtime_error;
	int autosuspend_delay;
	u64 last_busy;
	u64 active_time;
	u64 suspended_time;
	u64 accounting_timestamp;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device___3 *, s32);
	struct dev_pm_qos *qos;
};

struct device_type___3;

struct bus_type___3;

struct device_driver___3;

struct dev_pm_domain___3;

struct fwnode_handle___3;

struct class___3;

struct device___3 {
	struct kobject___3 kobj;
	struct device___3 *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type___3 *type;
	struct bus_type___3 *bus;
	struct device_driver___3 *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info___3 power;
	struct dev_pm_domain___3 *pm_domain;
	struct em_perf_domain *em_pd;
	struct dev_pin_info *pins;
	struct dev_msi_info msi;
	const struct dma_map_ops *dma_ops;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct cma *cma_area;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle___3 *fwnode;
	int numa_node;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	struct class___3 *class;
	const struct attribute_group___3 **groups;
	void (*release)(struct device___3 *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
};

struct block_device___3 {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	bool bd_read_only;
	dev_t bd_dev;
	atomic_t bd_openers;
	struct inode___3 *bd_inode;
	struct super_block___3 *bd_super;
	void *bd_claiming;
	struct device___3 bd_device;
	void *bd_holder;
	int bd_holders;
	bool bd_write_holder;
	struct kobject___3 *bd_holder_dir;
	u8 bd_partno;
	spinlock_t bd_size_lock;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	int bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct super_block___3 *bd_fsfreeze_sb;
	struct partition_meta_info *bd_meta_info;
};

typedef void bio_end_io_t___3(struct bio___3 *);

struct bio_vec___3 {
	struct page___3 *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct bio___3 {
	struct bio___3 *bi_next;
	struct block_device___3 *bi_bdev;
	blk_opf_t bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t___3 *bi_end_io;
	void *bi_private;
	struct blkcg_gq *bi_blkg;
	struct bio_issue bi_issue;
	u64 bi_iocost_cost;
	struct bio_crypt_ctx *bi_crypt_context;
	union {
		struct bio_integrity_payload *bi_integrity;
	};
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec___3 *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec___3 bi_inline_vecs[0];
};

struct dev_pagemap_ops___3 {
	void (*page_free)(struct page___3 *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault___3 *);
	int (*memory_failure)(struct dev_pagemap___3 *, long unsigned int, long unsigned int, int);
};

struct ubuf_info___3;

struct msghdr___3 {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter___3 msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb___3 *msg_iocb;
	struct ubuf_info___3 *msg_ubuf;
	int (*sg_from_iter)(struct sock___3 *, struct sk_buff___3 *, struct iov_iter___3 *, size_t);
};

struct ubuf_info___3 {
	void (*callback)(struct sk_buff___3 *, struct ubuf_info___3 *, bool);
	refcount_t refcnt;
	u8 flags;
};

struct sk_buff___3 {
	union {
		struct {
			struct sk_buff___3 *next;
			struct sk_buff___3 *prev;
			union {
				struct net_device___3 *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	union {
		struct sock___3 *sk;
		int ip_defrag_offset;
	};
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff___3 *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};

struct socket_wq___3 {
	wait_queue_head_t wait;
	struct fasync_struct___3 *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
	long: 64;
};

struct proto_ops___3;

struct socket___3 {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file___3 *file;
	struct sock___3 *sk;
	const struct proto_ops___3 *ops;
	long: 64;
	long: 64;
	long: 64;
	struct socket_wq___3 wq;
};

typedef int (*sk_read_actor_t___3)(read_descriptor_t *, struct sk_buff___3 *, unsigned int, size_t);

typedef int (*skb_read_actor_t___3)(struct sock___3 *, struct sk_buff___3 *);

struct proto_ops___3 {
	int family;
	struct module___3 *owner;
	int (*release)(struct socket___3 *);
	int (*bind)(struct socket___3 *, struct sockaddr *, int);
	int (*connect)(struct socket___3 *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket___3 *, struct socket___3 *);
	int (*accept)(struct socket___3 *, struct socket___3 *, int, bool);
	int (*getname)(struct socket___3 *, struct sockaddr *, int);
	__poll_t (*poll)(struct file___3 *, struct socket___3 *, struct poll_table_struct___3 *);
	int (*ioctl)(struct socket___3 *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct socket___3 *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket___3 *, void *, bool, bool);
	int (*listen)(struct socket___3 *, int);
	int (*shutdown)(struct socket___3 *, int);
	int (*setsockopt)(struct socket___3 *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket___3 *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file___3 *, struct socket___3 *);
	int (*sendmsg)(struct socket___3 *, struct msghdr___3 *, size_t);
	int (*recvmsg)(struct socket___3 *, struct msghdr___3 *, size_t, int);
	int (*mmap)(struct file___3 *, struct socket___3 *, struct vm_area_struct___3 *);
	ssize_t (*sendpage)(struct socket___3 *, struct page___3 *, int, size_t, int);
	ssize_t (*splice_read)(struct socket___3 *, loff_t *, struct pipe_inode_info___3 *, size_t, unsigned int);
	int (*set_peek_off)(struct sock___3 *, int);
	int (*peek_len)(struct socket___3 *);
	int (*read_sock)(struct sock___3 *, read_descriptor_t *, sk_read_actor_t___3);
	int (*read_skb)(struct sock___3 *, skb_read_actor_t___3);
	int (*sendpage_locked)(struct sock___3 *, struct page___3 *, int, size_t, int);
	int (*sendmsg_locked)(struct sock___3 *, struct msghdr___3 *, size_t);
	int (*set_rcvlowat)(struct sock___3 *, int);
};

struct net___3 {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	atomic_t dev_unreg_count;
	unsigned int dev_base_seq;
	int ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node cleanup_list;
	struct key_tag *key_domain;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
	struct sock___3 *rtnl;
	struct sock___3 *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device___3 *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_ipv4 ipv4;
	struct netns_ipv6 ipv6;
	struct netns_ieee802154_lowpan ieee802154_lowpan;
	struct netns_sctp sctp;
	struct netns_nf nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct netns_ft ft;
	struct sk_buff_head___3 wext_nlevents;
	struct net_generic *gen;
	struct netns_bpf bpf;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_xfrm xfrm;
	u64 net_cookie;
	struct netns_ipvs *ipvs;
	struct netns_mpls mpls;
	struct netns_can can;
	struct netns_xdp xdp;
	struct netns_mctp mctp;
	struct sock___3 *crypto_nlsk;
	struct sock___3 *diag_nlsk;
	struct netns_smc smc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct dev_pm_ops___3 {
	int (*prepare)(struct device___3 *);
	void (*complete)(struct device___3 *);
	int (*suspend)(struct device___3 *);
	int (*resume)(struct device___3 *);
	int (*freeze)(struct device___3 *);
	int (*thaw)(struct device___3 *);
	int (*poweroff)(struct device___3 *);
	int (*restore)(struct device___3 *);
	int (*suspend_late)(struct device___3 *);
	int (*resume_early)(struct device___3 *);
	int (*freeze_late)(struct device___3 *);
	int (*thaw_early)(struct device___3 *);
	int (*poweroff_late)(struct device___3 *);
	int (*restore_early)(struct device___3 *);
	int (*suspend_noirq)(struct device___3 *);
	int (*resume_noirq)(struct device___3 *);
	int (*freeze_noirq)(struct device___3 *);
	int (*thaw_noirq)(struct device___3 *);
	int (*poweroff_noirq)(struct device___3 *);
	int (*restore_noirq)(struct device___3 *);
	int (*runtime_suspend)(struct device___3 *);
	int (*runtime_resume)(struct device___3 *);
	int (*runtime_idle)(struct device___3 *);
};

struct wakeup_source___3 {
	const char *name;
	int id;
	struct list_head entry;
	spinlock_t lock;
	struct wake_irq *wakeirq;
	struct timer_list timer;
	long unsigned int timer_expires;
	ktime_t total_time;
	ktime_t max_time;
	ktime_t last_time;
	ktime_t start_prevent_time;
	ktime_t prevent_sleep_time;
	long unsigned int event_count;
	long unsigned int active_count;
	long unsigned int relax_count;
	long unsigned int expire_count;
	long unsigned int wakeup_count;
	struct device___3 *dev;
	bool active: 1;
	bool autosleep_enabled: 1;
};

struct dev_pm_domain___3 {
	struct dev_pm_ops___3 ops;
	int (*start)(struct device___3 *);
	void (*detach)(struct device___3 *, bool);
	int (*activate)(struct device___3 *);
	void (*sync)(struct device___3 *);
	void (*dismiss)(struct device___3 *);
};

struct bus_type___3 {
	const char *name;
	const char *dev_name;
	struct device___3 *dev_root;
	const struct attribute_group___3 **bus_groups;
	const struct attribute_group___3 **dev_groups;
	const struct attribute_group___3 **drv_groups;
	int (*match)(struct device___3 *, struct device_driver___3 *);
	int (*uevent)(struct device___3 *, struct kobj_uevent_env *);
	int (*probe)(struct device___3 *);
	void (*sync_state)(struct device___3 *);
	void (*remove)(struct device___3 *);
	void (*shutdown)(struct device___3 *);
	int (*online)(struct device___3 *);
	int (*offline)(struct device___3 *);
	int (*suspend)(struct device___3 *, pm_message_t);
	int (*resume)(struct device___3 *);
	int (*num_vf)(struct device___3 *);
	int (*dma_configure)(struct device___3 *);
	void (*dma_cleanup)(struct device___3 *);
	const struct dev_pm_ops___3 *pm;
	const struct iommu_ops *iommu_ops;
	struct subsys_private *p;
	struct lock_class_key lock_key;
	bool need_parent_lock;
};

struct device_driver___3 {
	const char *name;
	struct bus_type___3 *bus;
	struct module___3 *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device___3 *);
	void (*sync_state)(struct device___3 *);
	int (*remove)(struct device___3 *);
	void (*shutdown)(struct device___3 *);
	int (*suspend)(struct device___3 *, pm_message_t);
	int (*resume)(struct device___3 *);
	const struct attribute_group___3 **groups;
	const struct attribute_group___3 **dev_groups;
	const struct dev_pm_ops___3 *pm;
	void (*coredump)(struct device___3 *);
	struct driver_private *p;
};

struct device_type___3 {
	const char *name;
	const struct attribute_group___3 **groups;
	int (*uevent)(struct device___3 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___3 *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device___3 *);
	const struct dev_pm_ops___3 *pm;
};

struct class___3 {
	const char *name;
	struct module___3 *owner;
	const struct attribute_group___3 **class_groups;
	const struct attribute_group___3 **dev_groups;
	struct kobject___3 *dev_kobj;
	int (*dev_uevent)(struct device___3 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___3 *, umode_t *);
	void (*class_release)(struct class___3 *);
	void (*dev_release)(struct device___3 *);
	int (*shutdown_pre)(struct device___3 *);
	const struct kobj_ns_type_operations___3 *ns_type;
	const void * (*namespace)(struct device___3 *);
	void (*get_ownership)(struct device___3 *, kuid_t *, kgid_t *);
	const struct dev_pm_ops___3 *pm;
	struct subsys_private *p;
};

struct fwnode_operations___3;

struct fwnode_handle___3 {
	struct fwnode_handle___3 *secondary;
	const struct fwnode_operations___3 *ops;
	struct device___3 *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

struct fwnode_reference_args___3;

struct fwnode_endpoint___3;

struct fwnode_operations___3 {
	struct fwnode_handle___3 * (*get)(struct fwnode_handle___3 *);
	void (*put)(struct fwnode_handle___3 *);
	bool (*device_is_available)(const struct fwnode_handle___3 *);
	const void * (*device_get_match_data)(const struct fwnode_handle___3 *, const struct device___3 *);
	bool (*device_dma_supported)(const struct fwnode_handle___3 *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle___3 *);
	bool (*property_present)(const struct fwnode_handle___3 *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle___3 *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle___3 *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle___3 *);
	const char * (*get_name_prefix)(const struct fwnode_handle___3 *);
	struct fwnode_handle___3 * (*get_parent)(const struct fwnode_handle___3 *);
	struct fwnode_handle___3 * (*get_next_child_node)(const struct fwnode_handle___3 *, struct fwnode_handle___3 *);
	struct fwnode_handle___3 * (*get_named_child_node)(const struct fwnode_handle___3 *, const char *);
	int (*get_reference_args)(const struct fwnode_handle___3 *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args___3 *);
	struct fwnode_handle___3 * (*graph_get_next_endpoint)(const struct fwnode_handle___3 *, struct fwnode_handle___3 *);
	struct fwnode_handle___3 * (*graph_get_remote_endpoint)(const struct fwnode_handle___3 *);
	struct fwnode_handle___3 * (*graph_get_port_parent)(struct fwnode_handle___3 *);
	int (*graph_parse_endpoint)(const struct fwnode_handle___3 *, struct fwnode_endpoint___3 *);
	void * (*iomap)(struct fwnode_handle___3 *, int);
	int (*irq_get)(const struct fwnode_handle___3 *, unsigned int);
	int (*add_links)(struct fwnode_handle___3 *);
};

struct fwnode_endpoint___3 {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle___3 *local_fwnode;
};

struct fwnode_reference_args___3 {
	struct fwnode_handle___3 *fwnode;
	unsigned int nargs;
	u64 args[8];
};

struct pipe_buf_operations___3;

struct pipe_buffer___3 {
	struct page___3 *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations___3 *ops;
	unsigned int flags;
	long unsigned int private;
};

struct pipe_buf_operations___3 {
	int (*confirm)(struct pipe_inode_info___3 *, struct pipe_buffer___3 *);
	void (*release)(struct pipe_inode_info___3 *, struct pipe_buffer___3 *);
	bool (*try_steal)(struct pipe_inode_info___3 *, struct pipe_buffer___3 *);
	bool (*get)(struct pipe_inode_info___3 *, struct pipe_buffer___3 *);
};

typedef rx_handler_result_t rx_handler_func_t___3(struct sk_buff___3 **);

struct net_device___3 {
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
	long unsigned int state;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct list_head ptype_specific;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	unsigned int flags;
	long long unsigned int priv_flags;
	const struct net_device_ops *netdev_ops;
	int ifindex;
	short unsigned int gflags;
	short unsigned int hard_header_len;
	unsigned int mtu;
	short unsigned int needed_headroom;
	short unsigned int needed_tailroom;
	netdev_features_t features;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	netdev_features_t gso_partial_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct iw_handler_def *wireless_handlers;
	struct iw_public_data *wireless_data;
	const struct ethtool_ops *ethtool_ops;
	const struct l3mdev_ops *l3mdev_ops;
	const struct ndisc_ops *ndisc_ops;
	const struct xfrmdev_ops *xfrmdev_ops;
	const struct tlsdev_ops *tlsdev_ops;
	const struct header_ops *header_ops;
	unsigned char operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	short unsigned int padded;
	spinlock_t addr_list_lock;
	int irq;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset___3 *queues_kset;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct inet6_dev *ip6_ptr;
	struct vlan_info *vlan_info;
	struct dsa_port *dsa_ptr;
	struct tipc_bearer *tipc_ptr;
	void *atalk_ptr;
	void *ax25_ptr;
	struct wireless_dev *ieee80211_ptr;
	struct wpan_dev *ieee802154_ptr;
	struct mpls_dev *mpls_ptr;
	struct mctp_dev *mctp_ptr;
	const unsigned char *dev_addr;
	struct netdev_rx_queue *_rx;
	unsigned int num_rx_queues;
	unsigned int real_num_rx_queues;
	struct bpf_prog *xdp_prog;
	long unsigned int gro_flush_timeout;
	int napi_defer_hard_irqs;
	unsigned int gro_max_size;
	rx_handler_func_t___3 *rx_handler;
	void *rx_handler_data;
	struct mini_Qdisc *miniq_ingress;
	struct netdev_queue *ingress_queue;
	struct nf_hook_entries *nf_hooks_ingress;
	unsigned char broadcast[32];
	struct cpu_rmap *rx_cpu_rmap;
	struct hlist_node index_hlist;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netdev_queue *_tx;
	unsigned int num_tx_queues;
	unsigned int real_num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct xps_dev_maps *xps_maps[2];
	struct mini_Qdisc *miniq_egress;
	struct nf_hook_entries *nf_hooks_egress;
	struct hlist_head qdisc_hash[16];
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	int *pcpu_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	enum {
		NETREG_UNINITIALIZED___3 = 0,
		NETREG_REGISTERED___3 = 1,
		NETREG_UNREGISTERING___3 = 2,
		NETREG_UNREGISTERED___3 = 3,
		NETREG_RELEASED___3 = 4,
		NETREG_DUMMY___3 = 5,
	} reg_state: 8;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED___3 = 0,
		RTNL_LINK_INITIALIZING___3 = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device___3 *);
	struct netpoll_info *npinfo;
	possible_net_t nd_net;
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	struct garp_port *garp_port;
	struct mrp_port *mrp_port;
	struct dm_hw_stat_delta *dm_private;
	struct device___3 dev;
	const struct attribute_group___3 *sysfs_groups[4];
	const struct attribute_group___3 *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	unsigned int gso_max_size;
	unsigned int tso_max_size;
	u16 gso_max_segs;
	u16 tso_max_segs;
	const struct dcbnl_rtnl_ops *dcbnl_ops;
	s16 num_tc;
	struct netdev_tc_txq tc_to_txq[16];
	u8 prio_tc_map[16];
	unsigned int fcoe_ddp_xid;
	struct netprio_map *priomap;
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	unsigned int wol_enabled: 1;
	unsigned int threaded: 1;
	struct list_head net_notifier_list;
	const struct macsec_ops *macsec_ops;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	long: 64;
	long: 64;
	long: 64;
};

typedef struct bio_vec___3 skb_frag_t___3;

struct skb_shared_info___3 {
	__u8 flags;
	__u8 meta_len;
	__u8 nr_frags;
	__u8 tx_flags;
	short unsigned int gso_size;
	short unsigned int gso_segs;
	struct sk_buff___3 *frag_list;
	struct skb_shared_hwtstamps hwtstamps;
	unsigned int gso_type;
	u32 tskey;
	atomic_t dataref;
	unsigned int xdp_frags_size;
	void *destructor_arg;
	skb_frag_t___3 frags[17];
};

typedef unsigned int nf_hookfn___2(void *, struct sk_buff___3 *, const struct nf_hook_state *);

struct ovs_header {
	int dp_ifindex;
};

enum ovs_datapath_cmd {
	OVS_DP_CMD_UNSPEC = 0,
	OVS_DP_CMD_NEW = 1,
	OVS_DP_CMD_DEL = 2,
	OVS_DP_CMD_GET = 3,
	OVS_DP_CMD_SET = 4,
};

enum ovs_datapath_attr {
	OVS_DP_ATTR_UNSPEC = 0,
	OVS_DP_ATTR_NAME = 1,
	OVS_DP_ATTR_UPCALL_PID = 2,
	OVS_DP_ATTR_STATS = 3,
	OVS_DP_ATTR_MEGAFLOW_STATS = 4,
	OVS_DP_ATTR_USER_FEATURES = 5,
	OVS_DP_ATTR_PAD = 6,
	OVS_DP_ATTR_MASKS_CACHE_SIZE = 7,
	OVS_DP_ATTR_PER_CPU_PIDS = 8,
	OVS_DP_ATTR_IFINDEX = 9,
	__OVS_DP_ATTR_MAX = 10,
};

struct ovs_dp_stats {
	__u64 n_hit;
	__u64 n_missed;
	__u64 n_lost;
	__u64 n_flows;
};

struct ovs_dp_megaflow_stats {
	__u64 n_mask_hit;
	__u32 n_masks;
	__u32 pad0;
	__u64 n_cache_hit;
	__u64 pad1;
};

struct ovs_vport_stats {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
};

enum ovs_packet_attr {
	OVS_PACKET_ATTR_UNSPEC = 0,
	OVS_PACKET_ATTR_PACKET = 1,
	OVS_PACKET_ATTR_KEY = 2,
	OVS_PACKET_ATTR_ACTIONS = 3,
	OVS_PACKET_ATTR_USERDATA = 4,
	OVS_PACKET_ATTR_EGRESS_TUN_KEY = 5,
	OVS_PACKET_ATTR_UNUSED1 = 6,
	OVS_PACKET_ATTR_UNUSED2 = 7,
	OVS_PACKET_ATTR_PROBE = 8,
	OVS_PACKET_ATTR_MRU = 9,
	OVS_PACKET_ATTR_LEN = 10,
	OVS_PACKET_ATTR_HASH = 11,
	__OVS_PACKET_ATTR_MAX = 12,
};

enum ovs_vport_attr {
	OVS_VPORT_ATTR_UNSPEC = 0,
	OVS_VPORT_ATTR_PORT_NO = 1,
	OVS_VPORT_ATTR_TYPE = 2,
	OVS_VPORT_ATTR_NAME = 3,
	OVS_VPORT_ATTR_OPTIONS = 4,
	OVS_VPORT_ATTR_UPCALL_PID = 5,
	OVS_VPORT_ATTR_STATS = 6,
	OVS_VPORT_ATTR_PAD = 7,
	OVS_VPORT_ATTR_IFINDEX = 8,
	OVS_VPORT_ATTR_NETNSID = 9,
	__OVS_VPORT_ATTR_MAX = 10,
};

enum ovs_flow_cmd {
	OVS_FLOW_CMD_UNSPEC = 0,
	OVS_FLOW_CMD_NEW = 1,
	OVS_FLOW_CMD_DEL = 2,
	OVS_FLOW_CMD_GET = 3,
	OVS_FLOW_CMD_SET = 4,
};

enum ovs_frag_type {
	OVS_FRAG_TYPE_NONE = 0,
	OVS_FRAG_TYPE_FIRST = 1,
	OVS_FRAG_TYPE_LATER = 2,
	__OVS_FRAG_TYPE_MAX = 3,
};

enum ovs_flow_attr {
	OVS_FLOW_ATTR_UNSPEC = 0,
	OVS_FLOW_ATTR_KEY = 1,
	OVS_FLOW_ATTR_ACTIONS = 2,
	OVS_FLOW_ATTR_STATS = 3,
	OVS_FLOW_ATTR_TCP_FLAGS = 4,
	OVS_FLOW_ATTR_USED = 5,
	OVS_FLOW_ATTR_CLEAR = 6,
	OVS_FLOW_ATTR_MASK = 7,
	OVS_FLOW_ATTR_PROBE = 8,
	OVS_FLOW_ATTR_UFID = 9,
	OVS_FLOW_ATTR_UFID_FLAGS = 10,
	OVS_FLOW_ATTR_PAD = 11,
	__OVS_FLOW_ATTR_MAX = 12,
};

enum ovs_pkt_hash_types {
	OVS_PACKET_HASH_SW_BIT = 0,
	OVS_PACKET_HASH_L4_BIT = 0,
};

struct kset___4;

struct kobj_type___4;

struct kernfs_node___4;

struct kobject___4 {
	const char *name;
	struct list_head entry;
	struct kobject___4 *parent;
	struct kset___4 *kset;
	const struct kobj_type___4 *ktype;
	struct kernfs_node___4 *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct module___4;

struct module_kobject___4 {
	struct kobject___4 kobj;
	struct module___4 *mod;
	struct kobject___4 *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct mod_tree_node___4 {
	struct module___4 *mod;
	struct latch_tree_node node;
};

struct module_layout___4 {
	void *base;
	unsigned int size;
	unsigned int text_size;
	unsigned int ro_size;
	unsigned int ro_after_init_size;
	struct mod_tree_node___4 mtn;
};

struct module_attribute___4;

struct kernel_param___4;

struct module___4 {
	enum module_state state;
	struct list_head list;
	char name[56];
	struct module_kobject___4 mkobj;
	struct module_attribute___4 *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject___4 *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param___4 *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool sig_ok;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	struct module_layout___4 core_layout;
	struct module_layout___4 init_layout;
	struct mod_arch_specific arch;
	long unsigned int taints;
	unsigned int num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map___3 *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	int num_static_call_sites;
	struct static_call_site *static_call_sites;
	int num_kunit_suites;
	struct kunit_suite **kunit_suites;
	bool klp;
	bool klp_alive;
	struct klp_modinfo *klp_info;
	unsigned int printk_index_size;
	struct pi_entry **printk_index_start;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
};

struct dentry___4;

struct super_block___4;

struct file_system_type___4 {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry___4 * (*mount)(struct file_system_type___4 *, int, const char *, void *);
	void (*kill_sb)(struct super_block___4 *);
	struct module___4 *owner;
	struct file_system_type___4 *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

struct page___4;

typedef struct page___4 *pgtable_t___4;

struct address_space___4;

struct page_pool___4;

struct mm_struct___4;

struct dev_pagemap___4;

struct page___4 {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space___4 *mapping;
			long unsigned int index;
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool___4 *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			union {
				long unsigned int dma_addr_upper;
				atomic_long_t pp_frag_count;
			};
		};
		struct {
			long unsigned int compound_head;
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			atomic_t compound_pincount;
			unsigned int compound_nr;
		};
		struct {
			long unsigned int _compound_pad_1;
			long unsigned int _compound_pad_2;
			struct list_head deferred_list;
		};
		struct {
			long unsigned int _pt_pad_1;
			pgtable_t___4 pmd_huge_pte;
			long unsigned int _pt_pad_2;
			union {
				struct mm_struct___4 *pt_mm;
				atomic_t pt_frag_refcount;
			};
			spinlock_t ptl;
		};
		struct {
			struct dev_pagemap___4 *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	long unsigned int memcg_data;
};

struct kernel_param_ops___4 {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param___4 *);
	int (*get)(char *, const struct kernel_param___4 *);
	void (*free)(void *);
};

struct file___4;

struct kiocb___4;

struct iov_iter___4;

struct poll_table_struct___4;

struct vm_area_struct___4;

struct inode___4;

struct file_lock___4;

struct pipe_inode_info___4;

struct seq_file___4;

struct file_operations___4 {
	struct module___4 *owner;
	loff_t (*llseek)(struct file___4 *, loff_t, int);
	ssize_t (*read)(struct file___4 *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file___4 *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb___4 *, struct iov_iter___4 *);
	ssize_t (*write_iter)(struct kiocb___4 *, struct iov_iter___4 *);
	int (*iopoll)(struct kiocb___4 *, struct io_comp_batch *, unsigned int);
	int (*iterate)(struct file___4 *, struct dir_context *);
	int (*iterate_shared)(struct file___4 *, struct dir_context *);
	__poll_t (*poll)(struct file___4 *, struct poll_table_struct___4 *);
	long int (*unlocked_ioctl)(struct file___4 *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file___4 *, unsigned int, long unsigned int);
	int (*mmap)(struct file___4 *, struct vm_area_struct___4 *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode___4 *, struct file___4 *);
	int (*flush)(struct file___4 *, fl_owner_t);
	int (*release)(struct inode___4 *, struct file___4 *);
	int (*fsync)(struct file___4 *, loff_t, loff_t, int);
	int (*fasync)(int, struct file___4 *, int);
	int (*lock)(struct file___4 *, int, struct file_lock___4 *);
	ssize_t (*sendpage)(struct file___4 *, struct page___4 *, int, size_t, loff_t *, int);
	long unsigned int (*get_unmapped_area)(struct file___4 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file___4 *, int, struct file_lock___4 *);
	ssize_t (*splice_write)(struct pipe_inode_info___4 *, struct file___4 *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file___4 *, loff_t *, struct pipe_inode_info___4 *, size_t, unsigned int);
	int (*setlease)(struct file___4 *, long int, struct file_lock___4 **, void **);
	long int (*fallocate)(struct file___4 *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file___4 *, struct file___4 *);
	ssize_t (*copy_file_range)(struct file___4 *, loff_t, struct file___4 *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file___4 *, loff_t, struct file___4 *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file___4 *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

struct page_frag___4 {
	struct page___4 *page;
	__u32 offset;
	__u32 size;
};

struct pid___2;

struct nsproxy___4;

struct signal_struct___4;

struct bio_list___4;

struct backing_dev_info___4;

struct css_set___4;

struct mem_cgroup___4;

struct vm_struct___4;

struct task_struct___4 {
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct___4 *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	const struct sched_class *sched_class;
	struct rb_node core_node;
	long unsigned int core_cookie;
	unsigned int core_occupation;
	struct task_group *sched_task_group;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_statistics stats;
	struct hlist_head preempt_notifiers;
	unsigned int btrace_seq;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct___4 *mm;
	struct mm_struct___4 *active_mm;
	struct task_rss_stat rss_stat;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	unsigned int sched_psi_wake_requeue: 1;
	int: 28;
	unsigned int sched_remote_wakeup: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int in_user_fault: 1;
	unsigned int in_lru_fault: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_page_owner: 1;
	unsigned int in_eventfd: 1;
	unsigned int pasid_activated: 1;
	unsigned int reported_split_lock: 1;
	unsigned int in_thrashing: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct___4 *real_parent;
	struct task_struct___4 *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct___4 *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid___2 *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_group;
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	struct vtime vtime;
	atomic_t tick_dep_mask;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	struct posix_cputimers_work posix_cputimers_work;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy___4 *nsproxy;
	struct signal_struct___4 *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct audit_context *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct___4 *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	void *journal_info;
	struct bio_list___4 *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct backing_dev_info___4 *backing_dev_info;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	unsigned int psi_flags;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
	struct css_set___4 *cgroups;
	struct list_head cg_list;
	u32 closid;
	u32 rmid;
	struct robust_list_head *robust_list;
	struct compat_robust_list_head *compat_robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	struct perf_event_context *perf_event_ctxp[2];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	long unsigned int preempt_disable_ip;
	struct mempolicy *mempolicy;
	short int il_prev;
	short int pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	long unsigned int numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct numa_group *numa_group;
	long unsigned int *numa_faults;
	long unsigned int total_numa_faults;
	long unsigned int numa_faults_locality[3];
	long unsigned int numa_pages_migrated;
	struct rseq *rseq;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	struct tlbflush_unmap_batch tlb_ubc;
	union {
		refcount_t rcu_users;
		struct callback_head rcu;
	};
	struct pipe_inode_info___4 *splice_pipe;
	struct page_frag___4 task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	int latency_record_count;
	struct latency_record latency_record[32];
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	struct kunit *kunit_test;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace_recursion;
	struct mem_cgroup___4 *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup___4 *active_memcg;
	struct request_queue *throttle_queue;
	struct uprobe_task *utask;
	unsigned int sequential_io;
	unsigned int sequential_io_avg;
	struct kmap_ctrl kmap_ctrl;
	int pagefault_disabled;
	struct task_struct___4 *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct___4 *stack_vm_area;
	refcount_t stack_refcount;
	int patch_state;
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	void *mce_vaddr;
	__u64 mce_kflags;
	u64 mce_addr;
	__u64 mce_ripv: 1;
	__u64 mce_whole_page: 1;
	__u64 __mce_reserved: 62;
	struct callback_head mce_kill_me;
	int mce_count;
	struct llist_head kretprobe_instances;
	struct llist_head rethooks;
	struct callback_head l1d_flush_kill;
	union rv_task_monitor rv[1];
	struct thread_struct thread;
};

struct mm_struct___4 {
	struct {
		struct maple_tree mm_mt;
		long unsigned int (*get_unmapped_area)(struct file___4 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int mmap_compat_base;
		long unsigned int mmap_compat_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		atomic_t mm_count;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[48];
		struct mm_rss_stat rss_stat;
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct___4 *owner;
		struct user_namespace *user_ns;
		struct file___4 *exe_file;
		struct mmu_notifier_subscriptions *notifier_subscriptions;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		atomic_t tlb_flush_batched;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		u32 pasid;
		long unsigned int ksm_merging_pages;
		long unsigned int ksm_rmap_items;
		struct {
			struct list_head list;
			long unsigned int bitmap;
			struct mem_cgroup___4 *memcg;
		} lru_gen;
	};
	long unsigned int cpu_bitmap[0];
};

struct vm_operations_struct___4;

struct vm_area_struct___4 {
	long unsigned int vm_start;
	long unsigned int vm_end;
	struct mm_struct___4 *vm_mm;
	pgprot_t vm_page_prot;
	long unsigned int vm_flags;
	union {
		struct {
			struct rb_node rb;
			long unsigned int rb_subtree_last;
		} shared;
		struct anon_vma_name *anon_name;
	};
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct___4 *vm_ops;
	long unsigned int vm_pgoff;
	struct file___4 *vm_file;
	void *vm_private_data;
	atomic_long_t swap_readahead_info;
	struct mempolicy *vm_policy;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

struct bin_attribute___4;

struct attribute_group___4 {
	const char *name;
	umode_t (*is_visible)(struct kobject___4 *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject___4 *, struct bin_attribute___4 *, int);
	struct attribute **attrs;
	struct bin_attribute___4 **bin_attrs;
};

struct seq_operations___4 {
	void * (*start)(struct seq_file___4 *, loff_t *);
	void (*stop)(struct seq_file___4 *, void *);
	void * (*next)(struct seq_file___4 *, void *, loff_t *);
	int (*show)(struct seq_file___4 *, void *);
};

struct pid_namespace___2;

struct upid___2 {
	int nr;
	struct pid_namespace___2 *ns;
};

struct pid_namespace___2 {
	struct idr idr;
	struct callback_head rcu;
	unsigned int pid_allocated;
	struct task_struct___4 *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace___2 *parent;
	struct fs_pin *bacct;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	int reboot;
	struct ns_common ns;
};

struct pid___2 {
	refcount_t count;
	unsigned int level;
	spinlock_t lock;
	struct hlist_head tasks[4];
	struct hlist_head inodes;
	wait_queue_head_t wait_pidfd;
	struct callback_head rcu;
	struct upid___2 numbers[1];
};

struct core_state___4;

struct signal_struct___4 {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct___4 *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct___4 *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state___4 *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	int posix_timer_id;
	struct list_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid___2 *pids[4];
	atomic_t tick_dep_mask;
	struct pid___2 *tty_old_pgrp;
	int leader;
	struct tty_struct___2 *tty;
	struct autogroup *autogroup;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	unsigned int audit_tty;
	struct tty_audit_buf *tty_audit_buf;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct___4 *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct net___4;

struct nsproxy___4 {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace___2 *pid_ns_for_children;
	struct net___4 *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct bio___4;

struct bio_list___4 {
	struct bio___4 *head;
	struct bio___4 *tail;
};

struct bdi_writeback___4 {
	struct backing_dev_info___4 *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	long unsigned int dirty_sleep;
	struct list_head bdi_node;
	struct percpu_ref refcnt;
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css;
	struct cgroup_subsys_state *blkcg_css;
	struct list_head memcg_node;
	struct list_head blkcg_node;
	struct list_head b_attached;
	struct list_head offline_node;
	union {
		struct work_struct release_work;
		struct callback_head rcu;
	};
};

struct device___4;

struct backing_dev_info___4 {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	struct bdi_writeback___4 wb;
	struct list_head wb_list;
	struct xarray cgwb_tree;
	struct mutex cgwb_release_mutex;
	struct rw_semaphore wb_switch_rwsem;
	wait_queue_head_t wb_waitq;
	struct device___4 *dev;
	char dev_name[64];
	struct device___4 *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry___4 *debug_dir;
};

struct cgroup___4;

struct css_set___4 {
	struct cgroup_subsys_state *subsys[13];
	refcount_t refcount;
	struct css_set___4 *dom_cset;
	struct cgroup___4 *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[13];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_src_preload_node;
	struct list_head mg_dst_preload_node;
	struct list_head mg_node;
	struct cgroup___4 *mg_src_cgrp;
	struct cgroup___4 *mg_dst_cgrp;
	struct css_set___4 *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
};

struct fasync_struct___4;

struct pipe_buffer___4;

struct pipe_inode_info___4 {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	bool note_loss;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	struct page___4 *tmp_page;
	struct fasync_struct___4 *fasync_readers;
	struct fasync_struct___4 *fasync_writers;
	struct pipe_buffer___4 *bufs;
	struct user_struct *user;
	struct watch_queue *watch_queue;
};

struct mem_cgroup___4 {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct page_counter memory;
	union {
		struct page_counter swap;
		struct page_counter memsw;
	};
	struct page_counter kmem;
	struct page_counter tcpmem;
	struct work_struct high_work;
	long unsigned int zswap_max;
	long unsigned int soft_limit;
	struct vmpressure vmpressure;
	bool oom_group;
	bool oom_lock;
	int under_oom;
	int swappiness;
	int oom_kill_disable;
	struct cgroup_file events_file;
	struct cgroup_file events_local_file;
	struct cgroup_file swap_events_file;
	struct mutex thresholds_lock;
	struct mem_cgroup_thresholds thresholds;
	struct mem_cgroup_thresholds memsw_thresholds;
	struct list_head oom_notify;
	long unsigned int move_charge_at_immigrate;
	spinlock_t move_lock;
	long unsigned int move_lock_flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct memcg_vmstats *vmstats;
	atomic_long_t memory_events[9];
	atomic_long_t memory_events_local[9];
	long unsigned int socket_pressure;
	bool tcpmem_active;
	int tcpmem_pressure;
	int kmemcg_id;
	struct obj_cgroup *objcg;
	struct list_head objcg_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	atomic_t moving_account;
	struct task_struct___4 *move_lock_task;
	struct memcg_vmstats_percpu *vmstats_percpu;
	struct list_head cgwb_list;
	struct wb_domain cgwb_domain;
	struct memcg_cgwb_frn cgwb_frn[4];
	struct list_head event_list;
	spinlock_t event_list_lock;
	struct deferred_split deferred_split_queue;
	struct lru_gen_mm_list mm_list;
	struct mem_cgroup_per_node *nodeinfo[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct vm_struct___4 {
	struct vm_struct___4 *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page___4 **pages;
	unsigned int page_order;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

struct address_space_operations___4;

struct address_space___4 {
	struct inode___4 *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	struct rw_semaphore i_mmap_rwsem;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations___4 *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t private_lock;
	struct list_head private_list;
	void *private_data;
};

struct page_pool_params___4 {
	unsigned int flags;
	unsigned int order;
	unsigned int pool_size;
	int nid;
	struct device___4 *dev;
	enum dma_data_direction dma_dir;
	unsigned int max_len;
	unsigned int offset;
	void (*init_callback)(struct page___4 *, void *);
	void *init_arg;
};

struct pp_alloc_cache___4 {
	u32 count;
	struct page___4 *cache[128];
};

struct page_pool___4 {
	struct page_pool_params___4 p;
	struct delayed_work release_dw;
	void (*disconnect)(void *);
	long unsigned int defer_start;
	long unsigned int defer_warn;
	u32 pages_state_hold_cnt;
	unsigned int frag_offset;
	struct page___4 *frag_page;
	long int frag_users;
	u32 xdp_mem_id;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct pp_alloc_cache___4 alloc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct ptr_ring ring;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct dev_pagemap_ops___4;

struct dev_pagemap___4 {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops___4 *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct range ranges[0];
	};
};

struct folio___4 {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space___4 *mapping;
			long unsigned int index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page___4 page;
	};
	long unsigned int _flags_1;
	long unsigned int __head;
	unsigned char _folio_dtor;
	unsigned char _folio_order;
	atomic_t _total_mapcount;
	atomic_t _pincount;
	unsigned int _folio_nr_pages;
};

struct vfsmount___4;

struct path___4 {
	struct vfsmount___4 *mnt;
	struct dentry___4 *dentry;
};

struct fown_struct___2 {
	rwlock_t lock;
	struct pid___2 *pid;
	enum pid_type pid_type;
	kuid_t uid;
	kuid_t euid;
	int signum;
};

struct file___4 {
	union {
		struct llist_node f_llist;
		struct callback_head f_rcuhead;
		unsigned int f_iocb_flags;
	};
	struct path___4 f_path;
	struct inode___4 *f_inode;
	const struct file_operations___4 *f_op;
	spinlock_t f_lock;
	atomic_long_t f_count;
	unsigned int f_flags;
	fmode_t f_mode;
	struct mutex f_pos_lock;
	loff_t f_pos;
	struct fown_struct___2 f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	u64 f_version;
	void *f_security;
	void *private_data;
	struct hlist_head *f_ep;
	struct address_space___4 *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};

struct vm_fault___4;

struct vm_operations_struct___4 {
	void (*open)(struct vm_area_struct___4 *);
	void (*close)(struct vm_area_struct___4 *);
	int (*may_split)(struct vm_area_struct___4 *, long unsigned int);
	int (*mremap)(struct vm_area_struct___4 *);
	int (*mprotect)(struct vm_area_struct___4 *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault___4 *);
	vm_fault_t (*huge_fault)(struct vm_fault___4 *, enum page_entry_size);
	vm_fault_t (*map_pages)(struct vm_fault___4 *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct___4 *);
	vm_fault_t (*page_mkwrite)(struct vm_fault___4 *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault___4 *);
	int (*access)(struct vm_area_struct___4 *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct___4 *);
	int (*set_policy)(struct vm_area_struct___4 *, struct mempolicy *);
	struct mempolicy * (*get_policy)(struct vm_area_struct___4 *, long unsigned int);
	struct page___4 * (*find_special_page)(struct vm_area_struct___4 *, long unsigned int);
};

struct vm_fault___4 {
	const struct {
		struct vm_area_struct___4 *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page___4 *cow_page;
	struct page___4 *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t___4 prealloc_pte;
};

struct bio_vec___4 {
	struct page___4 *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct iov_iter___4 {
	u8 iter_type;
	bool nofault;
	bool data_source;
	bool user_backed;
	union {
		size_t iov_offset;
		int last_offset;
	};
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec___4 *bvec;
		struct xarray *xarray;
		struct pipe_inode_info___4 *pipe;
		void *ubuf;
	};
	union {
		long unsigned int nr_segs;
		struct {
			unsigned int head;
			unsigned int start_head;
		};
		loff_t xarray_start;
	};
};

struct ubuf_info___4;

struct sock___4;

struct sk_buff___4;

struct msghdr___4 {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter___4 msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb___4 *msg_iocb;
	struct ubuf_info___4 *msg_ubuf;
	int (*sg_from_iter)(struct sock___4 *, struct sk_buff___4 *, struct iov_iter___4 *, size_t);
};

struct kiocb___4 {
	struct file___4 *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb___4 *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	struct wait_page_queue *ki_waitq;
};

struct ubuf_info___4 {
	void (*callback)(struct sk_buff___4 *, struct ubuf_info___4 *, bool);
	refcount_t refcnt;
	u8 flags;
};

struct sk_buff_list___4 {
	struct sk_buff___4 *next;
	struct sk_buff___4 *prev;
};

struct sk_buff_head___4 {
	union {
		struct {
			struct sk_buff___4 *next;
			struct sk_buff___4 *prev;
		};
		struct sk_buff_list___4 list;
	};
	__u32 qlen;
	spinlock_t lock;
};

struct dst_entry___2;

struct socket___4;

struct net_device___4;

struct sock___4 {
	struct sock_common __sk_common;
	struct dst_entry___2 *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	socket_lock_t sk_lock;
	atomic_t sk_drops;
	int sk_rcvlowat;
	struct sk_buff_head___4 sk_error_queue;
	struct sk_buff_head___4 sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	int sk_forward_alloc;
	u32 sk_reserved_mem;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	int sk_rcvbuf;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	struct xfrm_policy *sk_policy[2];
	struct dst_entry___2 *sk_dst_cache;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head___4 sk_write_queue;
	__s32 sk_peek_off;
	int sk_write_pending;
	__u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	long int sk_sndtimeo;
	struct timer_list sk_timer;
	__u32 sk_priority;
	__u32 sk_mark;
	long unsigned int sk_pacing_rate;
	long unsigned int sk_max_pacing_rate;
	struct page_frag___4 sk_frag;
	netdev_features_t sk_route_caps;
	int sk_gso_type;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	__u32 sk_txhash;
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_userlocks: 4;
	u8 sk_pacing_shift;
	u16 sk_type;
	u16 sk_protocol;
	u16 sk_gso_max_segs;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	u8 sk_txrehash;
	u8 sk_prefer_busy_poll;
	u16 sk_busy_poll_budget;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid___2 *sk_peer_pid;
	const struct cred *sk_peer_cred;
	long int sk_rcvtimeo;
	ktime_t sk_stamp;
	u16 sk_tsflags;
	u8 sk_shutdown;
	atomic_t sk_tskey;
	atomic_t sk_zckey;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	struct socket___4 *sk_socket;
	void *sk_user_data;
	void *sk_security;
	struct sock_cgroup_data sk_cgrp_data;
	struct mem_cgroup___4 *sk_memcg;
	void (*sk_state_change)(struct sock___4 *);
	void (*sk_data_ready)(struct sock___4 *);
	void (*sk_write_space)(struct sock___4 *);
	void (*sk_error_report)(struct sock___4 *);
	int (*sk_backlog_rcv)(struct sock___4 *, struct sk_buff___4 *);
	struct sk_buff___4 * (*sk_validate_xmit_skb)(struct sock___4 *, struct net_device___4 *, struct sk_buff___4 *);
	void (*sk_destruct)(struct sock___4 *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
	struct hlist_node sk_bind2_node;
};

struct sk_buff___4 {
	union {
		struct {
			struct sk_buff___4 *next;
			struct sk_buff___4 *prev;
			union {
				struct net_device___4 *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	union {
		struct sock___4 *sk;
		int ip_defrag_offset;
	};
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff___4 *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};

struct inet_frags___2;

struct fqdir___3 {
	long int high_thresh;
	long int low_thresh;
	int timeout;
	int max_dist;
	struct inet_frags___2 *f;
	struct net___4 *net;
	bool dead;
	long: 56;
	long: 64;
	long: 64;
	struct rhashtable rhashtable;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t mem;
	struct work_struct destroy_work;
	struct llist_node free_list;
	long: 64;
	long: 64;
};

struct inet_frag_queue___2;

struct inet_frags___2 {
	unsigned int qsize;
	void (*constructor)(struct inet_frag_queue___2 *, const void *);
	void (*destructor)(struct inet_frag_queue___2 *);
	void (*frag_expire)(struct timer_list *);
	struct kmem_cache *frags_cachep;
	const char *frags_cache_name;
	struct rhashtable_params rhash_params;
	refcount_t refcnt;
	struct completion completion;
};

struct ip_ra_chain___2;

struct fib_rules_ops___2;

struct fib_notifier_ops___2;

struct netns_ipv4___2 {
	struct inet_timewait_death_row tcp_death_row;
	struct ctl_table_header *forw_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *ipv4_hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *xfrm4_hdr;
	struct ipv4_devconf *devconf_all;
	struct ipv4_devconf *devconf_dflt;
	struct ip_ra_chain___2 *ra_chain;
	struct mutex ra_mutex;
	struct fib_rules_ops___2 *rules_ops;
	struct fib_table *fib_main;
	struct fib_table *fib_default;
	unsigned int fib_rules_require_fldissect;
	bool fib_has_custom_rules;
	bool fib_has_custom_local_routes;
	bool fib_offload_disabled;
	atomic_t fib_num_tclassid_users;
	struct hlist_head *fib_table_hash;
	struct sock___4 *fibnl;
	struct sock___4 *mc_autojoin_sk;
	struct inet_peer_base *peers;
	struct fqdir___3 *fqdir;
	u8 sysctl_icmp_echo_ignore_all;
	u8 sysctl_icmp_echo_enable_probe;
	u8 sysctl_icmp_echo_ignore_broadcasts;
	u8 sysctl_icmp_ignore_bogus_error_responses;
	u8 sysctl_icmp_errors_use_inbound_ifaddr;
	int sysctl_icmp_ratelimit;
	int sysctl_icmp_ratemask;
	u32 ip_rt_min_pmtu;
	int ip_rt_mtu_expires;
	int ip_rt_min_advmss;
	struct local_ports ip_local_ports;
	u8 sysctl_tcp_ecn;
	u8 sysctl_tcp_ecn_fallback;
	u8 sysctl_ip_default_ttl;
	u8 sysctl_ip_no_pmtu_disc;
	u8 sysctl_ip_fwd_use_pmtu;
	u8 sysctl_ip_fwd_update_priority;
	u8 sysctl_ip_nonlocal_bind;
	u8 sysctl_ip_autobind_reuse;
	u8 sysctl_ip_dynaddr;
	u8 sysctl_ip_early_demux;
	u8 sysctl_raw_l3mdev_accept;
	u8 sysctl_tcp_early_demux;
	u8 sysctl_udp_early_demux;
	u8 sysctl_nexthop_compat_mode;
	u8 sysctl_fwmark_reflect;
	u8 sysctl_tcp_fwmark_accept;
	u8 sysctl_tcp_l3mdev_accept;
	u8 sysctl_tcp_mtu_probing;
	int sysctl_tcp_mtu_probe_floor;
	int sysctl_tcp_base_mss;
	int sysctl_tcp_min_snd_mss;
	int sysctl_tcp_probe_threshold;
	u32 sysctl_tcp_probe_interval;
	int sysctl_tcp_keepalive_time;
	int sysctl_tcp_keepalive_intvl;
	u8 sysctl_tcp_keepalive_probes;
	u8 sysctl_tcp_syn_retries;
	u8 sysctl_tcp_synack_retries;
	u8 sysctl_tcp_syncookies;
	u8 sysctl_tcp_migrate_req;
	u8 sysctl_tcp_comp_sack_nr;
	int sysctl_tcp_reordering;
	u8 sysctl_tcp_retries1;
	u8 sysctl_tcp_retries2;
	u8 sysctl_tcp_orphan_retries;
	u8 sysctl_tcp_tw_reuse;
	int sysctl_tcp_fin_timeout;
	unsigned int sysctl_tcp_notsent_lowat;
	u8 sysctl_tcp_sack;
	u8 sysctl_tcp_window_scaling;
	u8 sysctl_tcp_timestamps;
	u8 sysctl_tcp_early_retrans;
	u8 sysctl_tcp_recovery;
	u8 sysctl_tcp_thin_linear_timeouts;
	u8 sysctl_tcp_slow_start_after_idle;
	u8 sysctl_tcp_retrans_collapse;
	u8 sysctl_tcp_stdurg;
	u8 sysctl_tcp_rfc1337;
	u8 sysctl_tcp_abort_on_overflow;
	u8 sysctl_tcp_fack;
	int sysctl_tcp_max_reordering;
	int sysctl_tcp_adv_win_scale;
	u8 sysctl_tcp_dsack;
	u8 sysctl_tcp_app_win;
	u8 sysctl_tcp_frto;
	u8 sysctl_tcp_nometrics_save;
	u8 sysctl_tcp_no_ssthresh_metrics_save;
	u8 sysctl_tcp_moderate_rcvbuf;
	u8 sysctl_tcp_tso_win_divisor;
	u8 sysctl_tcp_workaround_signed_windows;
	int sysctl_tcp_limit_output_bytes;
	int sysctl_tcp_challenge_ack_limit;
	int sysctl_tcp_min_rtt_wlen;
	u8 sysctl_tcp_min_tso_segs;
	u8 sysctl_tcp_tso_rtt_log;
	u8 sysctl_tcp_autocorking;
	u8 sysctl_tcp_reflect_tos;
	int sysctl_tcp_invalid_ratelimit;
	int sysctl_tcp_pacing_ss_ratio;
	int sysctl_tcp_pacing_ca_ratio;
	int sysctl_tcp_wmem[3];
	int sysctl_tcp_rmem[3];
	unsigned int sysctl_tcp_child_ehash_entries;
	long unsigned int sysctl_tcp_comp_sack_delay_ns;
	long unsigned int sysctl_tcp_comp_sack_slack_ns;
	int sysctl_max_syn_backlog;
	int sysctl_tcp_fastopen;
	const struct tcp_congestion_ops *tcp_congestion_control;
	struct tcp_fastopen_context *tcp_fastopen_ctx;
	unsigned int sysctl_tcp_fastopen_blackhole_timeout;
	atomic_t tfo_active_disable_times;
	long unsigned int tfo_active_disable_stamp;
	u32 tcp_challenge_timestamp;
	u32 tcp_challenge_count;
	int sysctl_udp_wmem_min;
	int sysctl_udp_rmem_min;
	u8 sysctl_fib_notify_on_flag_change;
	u8 sysctl_udp_l3mdev_accept;
	u8 sysctl_igmp_llm_reports;
	int sysctl_igmp_max_memberships;
	int sysctl_igmp_max_msf;
	int sysctl_igmp_qrv;
	struct ping_group_range ping_group_range;
	atomic_t dev_addr_genid;
	long unsigned int *sysctl_local_reserved_ports;
	int sysctl_ip_prot_sock;
	struct list_head mr_tables;
	struct fib_rules_ops___2 *mr_rules_ops;
	u32 sysctl_fib_multipath_hash_fields;
	u8 sysctl_fib_multipath_use_neigh;
	u8 sysctl_fib_multipath_hash_policy;
	struct fib_notifier_ops___2 *notifier_ops;
	unsigned int fib_seq;
	struct fib_notifier_ops___2 *ipmr_notifier_ops;
	unsigned int ipmr_seq;
	atomic_t rt_genid;
	siphash_key_t ip_id_key;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct neighbour___2;

struct dst_ops___2 {
	short unsigned int family;
	unsigned int gc_thresh;
	int (*gc)(struct dst_ops___2 *);
	struct dst_entry___2 * (*check)(struct dst_entry___2 *, __u32);
	unsigned int (*default_advmss)(const struct dst_entry___2 *);
	unsigned int (*mtu)(const struct dst_entry___2 *);
	u32 * (*cow_metrics)(struct dst_entry___2 *, long unsigned int);
	void (*destroy)(struct dst_entry___2 *);
	void (*ifdown)(struct dst_entry___2 *, struct net_device___4 *, int);
	struct dst_entry___2 * (*negative_advice)(struct dst_entry___2 *);
	void (*link_failure)(struct sk_buff___4 *);
	void (*update_pmtu)(struct dst_entry___2 *, struct sock___4 *, struct sk_buff___4 *, u32, bool);
	void (*redirect)(struct dst_entry___2 *, struct sock___4 *, struct sk_buff___4 *);
	int (*local_out)(struct net___4 *, struct sock___4 *, struct sk_buff___4 *);
	struct neighbour___2 * (*neigh_lookup)(const struct dst_entry___2 *, struct sk_buff___4 *, const void *);
	void (*confirm_neigh)(const struct dst_entry___2 *, const void *);
	struct kmem_cache *kmem_cachep;
	struct percpu_counter pcpuc_entries;
	long: 64;
	long: 64;
	long: 64;
};

struct fib6_info___2;

struct rt6_info___2;

struct fib6_table___2;

struct netns_ipv6___2 {
	struct dst_ops___2 ip6_dst_ops;
	struct netns_sysctl_ipv6 sysctl;
	struct ipv6_devconf *devconf_all;
	struct ipv6_devconf *devconf_dflt;
	struct inet_peer_base *peers;
	struct fqdir___3 *fqdir;
	struct fib6_info___2 *fib6_null_entry;
	struct rt6_info___2 *ip6_null_entry;
	struct rt6_statistics *rt6_stats;
	struct timer_list ip6_fib_timer;
	struct hlist_head *fib_table_hash;
	struct fib6_table___2 *fib6_main_tbl;
	struct list_head fib6_walkers;
	rwlock_t fib6_walker_lock;
	spinlock_t fib6_gc_lock;
	atomic_t ip6_rt_gc_expire;
	long unsigned int ip6_rt_last_gc;
	unsigned char flowlabel_has_excl;
	bool fib6_has_custom_rules;
	unsigned int fib6_rules_require_fldissect;
	unsigned int fib6_routes_require_src;
	struct rt6_info___2 *ip6_prohibit_entry;
	struct rt6_info___2 *ip6_blk_hole_entry;
	struct fib6_table___2 *fib6_local_tbl;
	struct fib_rules_ops___2 *fib6_rules_ops;
	struct sock___4 *ndisc_sk;
	struct sock___4 *tcp_sk;
	struct sock___4 *igmp_sk;
	struct sock___4 *mc_autojoin_sk;
	struct hlist_head *inet6_addr_lst;
	spinlock_t addrconf_hash_lock;
	struct delayed_work addr_chk_work;
	struct list_head mr6_tables;
	struct fib_rules_ops___2 *mr6_rules_ops;
	atomic_t dev_addr_genid;
	atomic_t fib6_sernum;
	struct seg6_pernet_data *seg6_data;
	struct fib_notifier_ops___2 *notifier_ops;
	struct fib_notifier_ops___2 *ip6mr_notifier_ops;
	unsigned int ipmr_seq;
	struct {
		struct hlist_head head;
		spinlock_t lock;
		u32 seq;
	} ip6addrlbl_table;
	struct ioam6_pernet_data *ioam6_data;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct netns_ieee802154_lowpan___2 {
	struct netns_sysctl_lowpan sysctl;
	struct fqdir___3 *fqdir;
};

struct netns_sctp___2 {
	struct sctp_mib *sctp_statistics;
	struct proc_dir_entry *proc_net_sctp;
	struct ctl_table_header *sysctl_header;
	struct sock___4 *ctl_sock;
	struct sock___4 *udp4_sock;
	struct sock___4 *udp6_sock;
	int udp_port;
	int encap_port;
	struct list_head local_addr_list;
	struct list_head addr_waitq;
	struct timer_list addr_wq_timer;
	struct list_head auto_asconf_splist;
	spinlock_t addr_wq_lock;
	spinlock_t local_addr_lock;
	unsigned int rto_initial;
	unsigned int rto_min;
	unsigned int rto_max;
	int rto_alpha;
	int rto_beta;
	int max_burst;
	int cookie_preserve_enable;
	char *sctp_hmac_alg;
	unsigned int valid_cookie_life;
	unsigned int sack_timeout;
	unsigned int hb_interval;
	unsigned int probe_interval;
	int max_retrans_association;
	int max_retrans_path;
	int max_retrans_init;
	int pf_retrans;
	int ps_retrans;
	int pf_enable;
	int pf_expose;
	int sndbuf_policy;
	int rcvbuf_policy;
	int default_auto_asconf;
	int addip_enable;
	int addip_noauth;
	int prsctp_enable;
	int reconf_enable;
	int auth_enable;
	int intl_enable;
	int ecn_enable;
	int scope_policy;
	int rwnd_upd_shift;
	long unsigned int max_autoclose;
};

struct netns_xfrm___2 {
	struct list_head state_all;
	struct hlist_head *state_bydst;
	struct hlist_head *state_bysrc;
	struct hlist_head *state_byspi;
	struct hlist_head *state_byseq;
	unsigned int state_hmask;
	unsigned int state_num;
	struct work_struct state_hash_work;
	struct list_head policy_all;
	struct hlist_head *policy_byidx;
	unsigned int policy_idx_hmask;
	struct hlist_head policy_inexact[3];
	struct xfrm_policy_hash policy_bydst[3];
	unsigned int policy_count[6];
	struct work_struct policy_hash_work;
	struct xfrm_policy_hthresh policy_hthresh;
	struct list_head inexact_bins;
	struct sock___4 *nlsk;
	struct sock___4 *nlsk_stash;
	u32 sysctl_aevent_etime;
	u32 sysctl_aevent_rseqth;
	int sysctl_larval_drop;
	u32 sysctl_acq_expires;
	u8 policy_default[3];
	struct ctl_table_header *sysctl_hdr;
	long: 64;
	long: 64;
	long: 64;
	struct dst_ops___2 xfrm4_dst_ops;
	struct dst_ops___2 xfrm6_dst_ops;
	spinlock_t xfrm_state_lock;
	seqcount_spinlock_t xfrm_state_hash_generation;
	seqcount_spinlock_t xfrm_policy_hash_generation;
	spinlock_t xfrm_policy_lock;
	struct mutex xfrm_cfg_mutex;
	long: 64;
	long: 64;
};

struct net___4 {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	atomic_t dev_unreg_count;
	unsigned int dev_base_seq;
	int ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node cleanup_list;
	struct key_tag *key_domain;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
	struct sock___4 *rtnl;
	struct sock___4 *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device___4 *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_ipv4___2 ipv4;
	struct netns_ipv6___2 ipv6;
	struct netns_ieee802154_lowpan___2 ieee802154_lowpan;
	struct netns_sctp___2 sctp;
	struct netns_nf nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct netns_ft ft;
	struct sk_buff_head___4 wext_nlevents;
	struct net_generic *gen;
	struct netns_bpf bpf;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_xfrm___2 xfrm;
	u64 net_cookie;
	struct netns_ipvs *ipvs;
	struct netns_mpls mpls;
	struct netns_can can;
	struct netns_xdp xdp;
	struct netns_mctp mctp;
	struct sock___4 *crypto_nlsk;
	struct sock___4 *diag_nlsk;
	struct netns_smc smc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct inet_frag_queue___2 {
	struct rhash_head node;
	union {
		struct frag_v4_compare_key v4;
		struct frag_v6_compare_key v6;
	} key;
	struct timer_list timer;
	spinlock_t lock;
	refcount_t refcnt;
	struct rb_root rb_fragments;
	struct sk_buff___4 *fragments_tail;
	struct sk_buff___4 *last_run_head;
	ktime_t stamp;
	int len;
	int meat;
	u8 mono_delivery_time;
	__u8 flags;
	u16 max_size;
	struct fqdir___3 *fqdir;
	struct callback_head rcu;
};

struct ip_ra_chain___2 {
	struct ip_ra_chain___2 *next;
	struct sock___4 *sk;
	union {
		void (*destructor)(struct sock *);
		struct sock *saved_sk;
	};
	struct callback_head rcu;
};

struct fib_rules_ops___2 {
	int family;
	struct list_head list;
	int rule_size;
	int addr_size;
	int unresolved_rules;
	int nr_goto_rules;
	unsigned int fib_rules_seq;
	int (*action)(struct fib_rule *, struct flowi *, int, struct fib_lookup_arg *);
	bool (*suppress)(struct fib_rule *, int, struct fib_lookup_arg *);
	int (*match)(struct fib_rule *, struct flowi *, int);
	int (*configure)(struct fib_rule *, struct sk_buff___4 *, struct fib_rule_hdr *, struct nlattr **, struct netlink_ext_ack *);
	int (*delete)(struct fib_rule *);
	int (*compare)(struct fib_rule *, struct fib_rule_hdr *, struct nlattr **);
	int (*fill)(struct fib_rule *, struct sk_buff___4 *, struct fib_rule_hdr *);
	size_t (*nlmsg_payload)(struct fib_rule *);
	void (*flush_cache)(struct fib_rules_ops___2 *);
	int nlgroup;
	struct list_head rules_list;
	struct module___4 *owner;
	struct net___4 *fro_net;
	struct callback_head rcu;
};

struct fib_notifier_ops___2 {
	int family;
	struct list_head list;
	unsigned int (*fib_seq_read)(struct net___4 *);
	int (*fib_dump)(struct net___4 *, struct notifier_block *, struct netlink_ext_ack *);
	struct module___4 *owner;
	struct callback_head rcu;
};

struct lruvec___4;

struct lru_gen_mm_walk___4 {
	struct lruvec___4 *lruvec;
	long unsigned int max_seq;
	long unsigned int next_addr;
	int nr_pages[40];
	int mm_stats[6];
	int batched;
	bool can_swap;
	bool force_scan;
};

struct pglist_data___4;

struct lruvec___4 {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
	struct lru_gen_struct lrugen;
	struct lru_gen_mm_state mm_state;
	struct pglist_data___4 *pgdat;
};

struct zone___4 {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long int lowmem_reserve[5];
	int node;
	struct pglist_data___4 *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high;
	int pageset_batch;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	long unsigned int present_early_pages;
	long unsigned int cma_pages;
	const char *name;
	long unsigned int nr_isolate_pageblock;
	seqlock_t span_seqlock;
	int initialized;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct free_area free_area[11];
	long unsigned int flags;
	spinlock_t lock;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int percpu_drift_mark;
	long unsigned int compact_cached_free_pfn;
	long unsigned int compact_cached_migrate_pfn[2];
	long unsigned int compact_init_migrate_pfn;
	long unsigned int compact_init_free_pfn;
	unsigned int compact_considered;
	unsigned int compact_defer_shift;
	int compact_order_failed;
	bool compact_blockskip_flush;
	bool contiguous;
	short: 16;
	struct cacheline_padding _pad3_;
	atomic_long_t vm_stat[11];
	atomic_long_t vm_numa_event[6];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct zoneref___4 {
	struct zone___4 *zone;
	int zone_idx;
};

struct zonelist___4 {
	struct zoneref___4 _zonerefs[5121];
};

struct pglist_data___4 {
	struct zone___4 node_zones[5];
	struct zonelist___4 node_zonelists[2];
	int nr_zones;
	spinlock_t node_size_lock;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct mutex kswapd_lock;
	struct task_struct___4 *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct___4 *kcompactd;
	bool proactive_compact_trigger;
	long unsigned int totalreserve_pages;
	long unsigned int min_unmapped_pages;
	long unsigned int min_slab_pages;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct deferred_split deferred_split_queue;
	unsigned int nbp_rl_start;
	long unsigned int nbp_rl_nr_cand;
	unsigned int nbp_threshold;
	unsigned int nbp_th_start;
	long unsigned int nbp_th_nr_cand;
	struct lruvec___4 __lruvec;
	long unsigned int flags;
	struct lru_gen_mm_walk___4 mm_walk;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[43];
	struct memory_tier *memtier;
	long: 64;
	long: 64;
	long: 64;
};

struct dst_entry___2 {
	struct net_device___4 *dev;
	struct dst_ops___2 *ops;
	long unsigned int _metrics;
	long unsigned int expires;
	struct xfrm_state *xfrm;
	int (*input)(struct sk_buff___4 *);
	int (*output)(struct net___4 *, struct sock___4 *, struct sk_buff___4 *);
	short unsigned int flags;
	short int obsolete;
	short unsigned int header_len;
	short unsigned int trailer_len;
	atomic_t __refcnt;
	int __use;
	long unsigned int lastuse;
	struct lwtunnel_state *lwtstate;
	struct callback_head callback_head;
	short int error;
	short int __pad;
	__u32 tclassid;
	netdevice_tracker dev_tracker;
};

typedef rx_handler_result_t rx_handler_func_t___4(struct sk_buff___4 **);

struct wakeup_source___4;

struct dev_pm_info___4 {
	pm_message_t power_state;
	unsigned int can_wakeup: 1;
	unsigned int async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	struct list_head entry;
	struct completion completion;
	struct wakeup_source___4 *wakeup;
	bool wakeup_path: 1;
	bool syscore: 1;
	bool no_pm_callbacks: 1;
	unsigned int must_resume: 1;
	unsigned int may_skip_resume: 1;
	struct hrtimer suspend_timer;
	u64 timer_expires;
	struct work_struct work;
	wait_queue_head_t wait_queue;
	struct wake_irq *wakeirq;
	atomic_t usage_count;
	atomic_t child_count;
	unsigned int disable_depth: 3;
	unsigned int idle_notification: 1;
	unsigned int request_pending: 1;
	unsigned int deferred_resume: 1;
	unsigned int needs_force_resume: 1;
	unsigned int runtime_auto: 1;
	bool ignore_children: 1;
	unsigned int no_callbacks: 1;
	unsigned int irq_safe: 1;
	unsigned int use_autosuspend: 1;
	unsigned int timer_autosuspends: 1;
	unsigned int memalloc_noio: 1;
	unsigned int links_count;
	enum rpm_request request;
	enum rpm_status runtime_status;
	enum rpm_status last_status;
	int runtime_error;
	int autosuspend_delay;
	u64 last_busy;
	u64 active_time;
	u64 suspended_time;
	u64 accounting_timestamp;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device___4 *, s32);
	struct dev_pm_qos *qos;
};

struct device_type___4;

struct bus_type___4;

struct device_driver___4;

struct dev_pm_domain___4;

struct fwnode_handle___4;

struct class___4;

struct device___4 {
	struct kobject___4 kobj;
	struct device___4 *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type___4 *type;
	struct bus_type___4 *bus;
	struct device_driver___4 *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info___4 power;
	struct dev_pm_domain___4 *pm_domain;
	struct em_perf_domain *em_pd;
	struct dev_pin_info *pins;
	struct dev_msi_info msi;
	const struct dma_map_ops *dma_ops;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct cma *cma_area;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle___4 *fwnode;
	int numa_node;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	struct class___4 *class;
	const struct attribute_group___4 **groups;
	void (*release)(struct device___4 *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
};

struct net_device___4 {
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
	long unsigned int state;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct list_head ptype_specific;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	unsigned int flags;
	long long unsigned int priv_flags;
	const struct net_device_ops *netdev_ops;
	int ifindex;
	short unsigned int gflags;
	short unsigned int hard_header_len;
	unsigned int mtu;
	short unsigned int needed_headroom;
	short unsigned int needed_tailroom;
	netdev_features_t features;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	netdev_features_t gso_partial_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct iw_handler_def *wireless_handlers;
	struct iw_public_data *wireless_data;
	const struct ethtool_ops *ethtool_ops;
	const struct l3mdev_ops *l3mdev_ops;
	const struct ndisc_ops *ndisc_ops;
	const struct xfrmdev_ops *xfrmdev_ops;
	const struct tlsdev_ops *tlsdev_ops;
	const struct header_ops *header_ops;
	unsigned char operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	short unsigned int padded;
	spinlock_t addr_list_lock;
	int irq;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset___4 *queues_kset;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct inet6_dev *ip6_ptr;
	struct vlan_info *vlan_info;
	struct dsa_port *dsa_ptr;
	struct tipc_bearer *tipc_ptr;
	void *atalk_ptr;
	void *ax25_ptr;
	struct wireless_dev *ieee80211_ptr;
	struct wpan_dev *ieee802154_ptr;
	struct mpls_dev *mpls_ptr;
	struct mctp_dev *mctp_ptr;
	const unsigned char *dev_addr;
	struct netdev_rx_queue *_rx;
	unsigned int num_rx_queues;
	unsigned int real_num_rx_queues;
	struct bpf_prog *xdp_prog;
	long unsigned int gro_flush_timeout;
	int napi_defer_hard_irqs;
	unsigned int gro_max_size;
	rx_handler_func_t___4 *rx_handler;
	void *rx_handler_data;
	struct mini_Qdisc *miniq_ingress;
	struct netdev_queue *ingress_queue;
	struct nf_hook_entries *nf_hooks_ingress;
	unsigned char broadcast[32];
	struct cpu_rmap *rx_cpu_rmap;
	struct hlist_node index_hlist;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netdev_queue *_tx;
	unsigned int num_tx_queues;
	unsigned int real_num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct xps_dev_maps *xps_maps[2];
	struct mini_Qdisc *miniq_egress;
	struct nf_hook_entries *nf_hooks_egress;
	struct hlist_head qdisc_hash[16];
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	int *pcpu_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	enum {
		NETREG_UNINITIALIZED___4 = 0,
		NETREG_REGISTERED___4 = 1,
		NETREG_UNREGISTERING___4 = 2,
		NETREG_UNREGISTERED___4 = 3,
		NETREG_RELEASED___4 = 4,
		NETREG_DUMMY___4 = 5,
	} reg_state: 8;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED___4 = 0,
		RTNL_LINK_INITIALIZING___4 = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device___4 *);
	struct netpoll_info *npinfo;
	possible_net_t nd_net;
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	struct garp_port *garp_port;
	struct mrp_port *mrp_port;
	struct dm_hw_stat_delta *dm_private;
	struct device___4 dev;
	const struct attribute_group___4 *sysfs_groups[4];
	const struct attribute_group___4 *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	unsigned int gso_max_size;
	unsigned int tso_max_size;
	u16 gso_max_segs;
	u16 tso_max_segs;
	const struct dcbnl_rtnl_ops *dcbnl_ops;
	s16 num_tc;
	struct netdev_tc_txq tc_to_txq[16];
	u8 prio_tc_map[16];
	unsigned int fcoe_ddp_xid;
	struct netprio_map *priomap;
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	unsigned int wol_enabled: 1;
	unsigned int threaded: 1;
	struct list_head net_notifier_list;
	const struct macsec_ops *macsec_ops;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	long: 64;
	long: 64;
	long: 64;
};

struct neighbour___2 {
	struct neighbour___2 *next;
	struct neigh_table *tbl;
	struct neigh_parms *parms;
	long unsigned int confirmed;
	long unsigned int updated;
	rwlock_t lock;
	refcount_t refcnt;
	unsigned int arp_queue_len_bytes;
	struct sk_buff_head___4 arp_queue;
	struct timer_list timer;
	long unsigned int used;
	atomic_t probes;
	u8 nud_state;
	u8 type;
	u8 dead;
	u8 protocol;
	u32 flags;
	seqlock_t ha_lock;
	int: 32;
	unsigned char ha[32];
	struct hh_cache hh;
	int (*output)(struct neighbour___2 *, struct sk_buff___4 *);
	const struct neigh_ops *ops;
	struct list_head gc_list;
	struct list_head managed_list;
	struct callback_head rcu;
	struct net_device___4 *dev;
	netdevice_tracker dev_tracker;
	u8 primary_key[0];
};

struct fib6_info___2 {
	struct fib6_table___2 *fib6_table;
	struct fib6_info___2 *fib6_next;
	struct fib6_node *fib6_node;
	union {
		struct list_head fib6_siblings;
		struct list_head nh_list;
	};
	unsigned int fib6_nsiblings;
	refcount_t fib6_ref;
	long unsigned int expires;
	struct dst_metrics *fib6_metrics;
	struct rt6key fib6_dst;
	u32 fib6_flags;
	struct rt6key fib6_src;
	struct rt6key fib6_prefsrc;
	u32 fib6_metric;
	u8 fib6_protocol;
	u8 fib6_type;
	u8 offload;
	u8 trap;
	u8 offload_failed;
	u8 should_flush: 1;
	u8 dst_nocount: 1;
	u8 dst_nopolicy: 1;
	u8 fib6_destroying: 1;
	u8 unused: 4;
	struct callback_head rcu;
	struct nexthop *nh;
	struct fib6_nh fib6_nh[0];
};

struct rt6_info___2 {
	struct dst_entry___2 dst;
	struct fib6_info___2 *from;
	int sernum;
	struct rt6key rt6i_dst;
	struct rt6key rt6i_src;
	struct in6_addr rt6i_gateway;
	struct inet6_dev *rt6i_idev;
	u32 rt6i_flags;
	struct list_head rt6i_uncached;
	struct uncached_list *rt6i_uncached_list;
	short unsigned int rt6i_nfheader_len;
};

struct fib6_table___2 {
	struct hlist_node tb6_hlist;
	u32 tb6_id;
	spinlock_t tb6_lock;
	struct fib6_node tb6_root;
	struct inet_peer_base tb6_peers;
	unsigned int flags;
	unsigned int fib_seq;
};

struct dentry_operations___4;

struct dentry___4 {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry___4 *d_parent;
	struct qstr d_name;
	struct inode___4 *d_inode;
	unsigned char d_iname[32];
	struct lockref d_lockref;
	const struct dentry_operations___4 *d_op;
	struct super_block___4 *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct list_head d_child;
	struct list_head d_subdirs;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

struct inode_operations___4;

struct inode___4 {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations___4 *i_op;
	struct super_block___4 *i_sb;
	struct address_space___4 *i_mapping;
	void *i_security;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback___4 *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations___4 *i_fop;
		void (*free_inode)(struct inode___4 *);
	};
	struct file_lock_context *i_flctx;
	struct address_space___4 i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info___4 *i_pipe;
		struct cdev___2 *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_info *i_crypt_info;
	struct fsverity_info *i_verity_info;
	void *i_private;
};

struct dentry_operations___4 {
	int (*d_revalidate)(struct dentry___4 *, unsigned int);
	int (*d_weak_revalidate)(struct dentry___4 *, unsigned int);
	int (*d_hash)(const struct dentry___4 *, struct qstr *);
	int (*d_compare)(const struct dentry___4 *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry___4 *);
	int (*d_init)(struct dentry___4 *);
	void (*d_release)(struct dentry___4 *);
	void (*d_prune)(struct dentry___4 *);
	void (*d_iput)(struct dentry___4 *, struct inode___4 *);
	char * (*d_dname)(struct dentry___4 *, char *, int);
	struct vfsmount___4 * (*d_automount)(struct path___4 *);
	int (*d_manage)(const struct path___4 *, bool);
	struct dentry___4 * (*d_real)(struct dentry___4 *, const struct inode___4 *);
	long: 64;
	long: 64;
	long: 64;
};

struct quota_format_type___4;

struct mem_dqinfo___4 {
	struct quota_format_type___4 *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};

struct quota_format_ops___4;

struct quota_info___4 {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode___4 *files[3];
	struct mem_dqinfo___4 info[3];
	const struct quota_format_ops___4 *ops[3];
};

struct rcuwait___4 {
	struct task_struct___4 *task;
};

struct percpu_rw_semaphore___4 {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait___4 writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers___4 {
	int frozen;
	wait_queue_head_t wait_unfrozen;
	struct percpu_rw_semaphore___4 rw_sem[3];
};

struct shrink_control___4;

struct shrinker___4 {
	long unsigned int (*count_objects)(struct shrinker___4 *, struct shrink_control___4 *);
	long unsigned int (*scan_objects)(struct shrinker___4 *, struct shrink_control___4 *);
	long int batch;
	int seeks;
	unsigned int flags;
	struct list_head list;
	int id;
	atomic_long_t *nr_deferred;
};

struct super_operations___4;

struct dquot_operations___4;

struct quotactl_ops___4;

struct block_device___4;

struct super_block___4 {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type___4 *s_type;
	const struct super_operations___4 *s_op;
	const struct dquot_operations___4 *dq_op;
	const struct quotactl_ops___4 *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry___4 *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	void *s_security;
	const struct xattr_handler **s_xattr;
	const struct fscrypt_operations *s_cop;
	struct fscrypt_keyring *s_master_keys;
	const struct fsverity_operations *s_vop;
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device___4 *s_bdev;
	struct backing_dev_info___4 *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info___4 s_dquot;
	struct sb_writers___4 s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	__u32 s_fsnotify_mask;
	struct fsnotify_mark_connector *s_fsnotify_marks;
	char s_id[32];
	uuid_t s_uuid;
	unsigned int s_max_links;
	fmode_t s_mode;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations___4 *s_d_op;
	struct shrinker___4 s_shrink;
	atomic_long_t s_remove_count;
	atomic_long_t s_fsnotify_connectors;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 64;
	long: 64;
};

struct vfsmount___4 {
	struct dentry___4 *mnt_root;
	struct super_block___4 *mnt_sb;
	int mnt_flags;
	struct user_namespace *mnt_userns;
};

struct shrink_control___4 {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup___4 *memcg;
};

struct cgroup___4 {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	struct kernfs_node___4 *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	struct cgroup_file psi_files[4];
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[13];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[13];
	struct cgroup___4 *dom_cgrp;
	struct cgroup___4 *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group *psi;
	struct cgroup_bpf bpf;
	atomic_t congestion_count;
	struct cgroup_freezer_state freezer;
	struct cgroup___4 *ancestors[0];
};

struct core_thread___4 {
	struct task_struct___4 *task;
	struct core_thread___4 *next;
};

struct core_state___4 {
	atomic_t nr_threads;
	struct core_thread___4 dumper;
	struct completion startup;
};

struct iattr___4 {
	unsigned int ia_valid;
	umode_t ia_mode;
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file___4 *ia_file;
};

struct dquot___4 {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block___4 *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};

struct quota_format_type___4 {
	int qf_fmt_id;
	const struct quota_format_ops___4 *qf_ops;
	struct module___4 *qf_owner;
	struct quota_format_type___4 *qf_next;
};

struct quota_format_ops___4 {
	int (*check_quota_file)(struct super_block___4 *, int);
	int (*read_file_info)(struct super_block___4 *, int);
	int (*write_file_info)(struct super_block___4 *, int);
	int (*free_file_info)(struct super_block___4 *, int);
	int (*read_dqblk)(struct dquot___4 *);
	int (*commit_dqblk)(struct dquot___4 *);
	int (*release_dqblk)(struct dquot___4 *);
	int (*get_next_id)(struct super_block___4 *, struct kqid *);
};

struct dquot_operations___4 {
	int (*write_dquot)(struct dquot___4 *);
	struct dquot___4 * (*alloc_dquot)(struct super_block___4 *, int);
	void (*destroy_dquot)(struct dquot___4 *);
	int (*acquire_dquot)(struct dquot___4 *);
	int (*release_dquot)(struct dquot___4 *);
	int (*mark_dirty)(struct dquot___4 *);
	int (*write_info)(struct super_block___4 *, int);
	qsize_t * (*get_reserved_space)(struct inode___4 *);
	int (*get_projid)(struct inode___4 *, kprojid_t *);
	int (*get_inode_usage)(struct inode___4 *, qsize_t *);
	int (*get_next_id)(struct super_block___4 *, struct kqid *);
};

struct quotactl_ops___4 {
	int (*quota_on)(struct super_block___4 *, int, int, const struct path___4 *);
	int (*quota_off)(struct super_block___4 *, int);
	int (*quota_enable)(struct super_block___4 *, unsigned int);
	int (*quota_disable)(struct super_block___4 *, unsigned int);
	int (*quota_sync)(struct super_block___4 *, int);
	int (*set_info)(struct super_block___4 *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block___4 *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block___4 *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block___4 *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block___4 *, struct qc_state *);
	int (*rm_xquota)(struct super_block___4 *, unsigned int);
};

struct writeback_control___4;

struct address_space_operations___4 {
	int (*writepage)(struct page___4 *, struct writeback_control___4 *);
	int (*read_folio)(struct file___4 *, struct folio___4 *);
	int (*writepages)(struct address_space___4 *, struct writeback_control___4 *);
	bool (*dirty_folio)(struct address_space___4 *, struct folio___4 *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file___4 *, struct address_space___4 *, loff_t, unsigned int, struct page___4 **, void **);
	int (*write_end)(struct file___4 *, struct address_space___4 *, loff_t, unsigned int, unsigned int, struct page___4 *, void *);
	sector_t (*bmap)(struct address_space___4 *, sector_t);
	void (*invalidate_folio)(struct folio___4 *, size_t, size_t);
	bool (*release_folio)(struct folio___4 *, gfp_t);
	void (*free_folio)(struct folio___4 *);
	ssize_t (*direct_IO)(struct kiocb___4 *, struct iov_iter___4 *);
	int (*migrate_folio)(struct address_space___4 *, struct folio___4 *, struct folio___4 *, enum migrate_mode);
	int (*launder_folio)(struct folio___4 *);
	bool (*is_partially_uptodate)(struct folio___4 *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio___4 *, bool *, bool *);
	int (*error_remove_page)(struct address_space___4 *, struct page___4 *);
	int (*swap_activate)(struct swap_info_struct *, struct file___4 *, sector_t *);
	void (*swap_deactivate)(struct file___4 *);
	int (*swap_rw)(struct kiocb___4 *, struct iov_iter___4 *);
};

struct writeback_control___4 {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_fscache_wb: 1;
	unsigned int no_cgroup_owner: 1;
	unsigned int punt_to_cgroup: 1;
	struct swap_iocb **swap_plug;
	struct bdi_writeback___4 *wb;
	struct inode___4 *inode;
	int wb_id;
	int wb_lcand_id;
	int wb_tcand_id;
	size_t wb_bytes;
	size_t wb_lcand_bytes;
	size_t wb_tcand_bytes;
};

struct inode_operations___4 {
	struct dentry___4 * (*lookup)(struct inode___4 *, struct dentry___4 *, unsigned int);
	const char * (*get_link)(struct dentry___4 *, struct inode___4 *, struct delayed_call *);
	int (*permission)(struct user_namespace *, struct inode___4 *, int);
	struct posix_acl * (*get_acl)(struct inode___4 *, int, bool);
	int (*readlink)(struct dentry___4 *, char *, int);
	int (*create)(struct user_namespace *, struct inode___4 *, struct dentry___4 *, umode_t, bool);
	int (*link)(struct dentry___4 *, struct inode___4 *, struct dentry___4 *);
	int (*unlink)(struct inode___4 *, struct dentry___4 *);
	int (*symlink)(struct user_namespace *, struct inode___4 *, struct dentry___4 *, const char *);
	int (*mkdir)(struct user_namespace *, struct inode___4 *, struct dentry___4 *, umode_t);
	int (*rmdir)(struct inode___4 *, struct dentry___4 *);
	int (*mknod)(struct user_namespace *, struct inode___4 *, struct dentry___4 *, umode_t, dev_t);
	int (*rename)(struct user_namespace *, struct inode___4 *, struct dentry___4 *, struct inode___4 *, struct dentry___4 *, unsigned int);
	int (*setattr)(struct user_namespace *, struct dentry___4 *, struct iattr___4 *);
	int (*getattr)(struct user_namespace *, const struct path___4 *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry___4 *, char *, size_t);
	int (*fiemap)(struct inode___4 *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode___4 *, struct timespec64 *, int);
	int (*atomic_open)(struct inode___4 *, struct dentry___4 *, struct file___4 *, unsigned int, umode_t);
	int (*tmpfile)(struct user_namespace *, struct inode___4 *, struct file___4 *, umode_t);
	int (*set_acl)(struct user_namespace *, struct inode___4 *, struct posix_acl *, int);
	int (*fileattr_set)(struct user_namespace *, struct dentry___4 *, struct fileattr *);
	int (*fileattr_get)(struct dentry___4 *, struct fileattr *);
	long: 64;
};

struct file_lock_operations___4 {
	void (*fl_copy_lock)(struct file_lock___4 *, struct file_lock___4 *);
	void (*fl_release_private)(struct file_lock___4 *);
};

struct lock_manager_operations___4;

struct file_lock___4 {
	struct file_lock___4 *fl_blocker;
	struct list_head fl_list;
	struct hlist_node fl_link;
	struct list_head fl_blocked_requests;
	struct list_head fl_blocked_member;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	unsigned int fl_pid;
	int fl_link_cpu;
	wait_queue_head_t fl_wait;
	struct file___4 *fl_file;
	loff_t fl_start;
	loff_t fl_end;
	struct fasync_struct___4 *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct file_lock_operations___4 *fl_ops;
	const struct lock_manager_operations___4 *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
	} fl_u;
};

struct lock_manager_operations___4 {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock___4 *);
	int (*lm_grant)(struct file_lock___4 *, int);
	bool (*lm_break)(struct file_lock___4 *);
	int (*lm_change)(struct file_lock___4 *, int, struct list_head *);
	void (*lm_setup)(struct file_lock___4 *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lock___4 *);
	bool (*lm_lock_expirable)(struct file_lock___4 *);
	void (*lm_expire_lock)();
};

struct fasync_struct___4 {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct___4 *fa_next;
	struct file___4 *fa_file;
	struct callback_head fa_rcu;
};

struct super_operations___4 {
	struct inode___4 * (*alloc_inode)(struct super_block___4 *);
	void (*destroy_inode)(struct inode___4 *);
	void (*free_inode)(struct inode___4 *);
	void (*dirty_inode)(struct inode___4 *, int);
	int (*write_inode)(struct inode___4 *, struct writeback_control___4 *);
	int (*drop_inode)(struct inode___4 *);
	void (*evict_inode)(struct inode___4 *);
	void (*put_super)(struct super_block___4 *);
	int (*sync_fs)(struct super_block___4 *, int);
	int (*freeze_super)(struct super_block___4 *);
	int (*freeze_fs)(struct super_block___4 *);
	int (*thaw_super)(struct super_block___4 *);
	int (*unfreeze_fs)(struct super_block___4 *);
	int (*statfs)(struct dentry___4 *, struct kstatfs *);
	int (*remount_fs)(struct super_block___4 *, int *, char *);
	void (*umount_begin)(struct super_block___4 *);
	int (*show_options)(struct seq_file___4 *, struct dentry___4 *);
	int (*show_devname)(struct seq_file___4 *, struct dentry___4 *);
	int (*show_path)(struct seq_file___4 *, struct dentry___4 *);
	int (*show_stats)(struct seq_file___4 *, struct dentry___4 *);
	ssize_t (*quota_read)(struct super_block___4 *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block___4 *, int, const char *, size_t, loff_t);
	struct dquot___4 ** (*get_dquots)(struct inode___4 *);
	long int (*nr_cached_objects)(struct super_block___4 *, struct shrink_control___4 *);
	long int (*free_cached_objects)(struct super_block___4 *, struct shrink_control___4 *);
};

struct block_device___4 {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	bool bd_read_only;
	dev_t bd_dev;
	atomic_t bd_openers;
	struct inode___4 *bd_inode;
	struct super_block___4 *bd_super;
	void *bd_claiming;
	struct device___4 bd_device;
	void *bd_holder;
	int bd_holders;
	bool bd_write_holder;
	struct kobject___4 *bd_holder_dir;
	u8 bd_partno;
	spinlock_t bd_size_lock;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	int bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct super_block___4 *bd_fsfreeze_sb;
	struct partition_meta_info *bd_meta_info;
};

typedef void (*poll_queue_proc___4)(struct file___4 *, wait_queue_head_t *, struct poll_table_struct___4 *);

struct poll_table_struct___4 {
	poll_queue_proc___4 _qproc;
	__poll_t _key;
};

struct seq_file___4 {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations___4 *op;
	int poll_event;
	const struct file___4 *file;
	void *private;
};

typedef void bio_end_io_t___4(struct bio___4 *);

struct bio___4 {
	struct bio___4 *bi_next;
	struct block_device___4 *bi_bdev;
	blk_opf_t bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t___4 *bi_end_io;
	void *bi_private;
	struct blkcg_gq *bi_blkg;
	struct bio_issue bi_issue;
	u64 bi_iocost_cost;
	struct bio_crypt_ctx *bi_crypt_context;
	union {
		struct bio_integrity_payload *bi_integrity;
	};
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec___4 *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec___4 bi_inline_vecs[0];
};

struct dev_pagemap_ops___4 {
	void (*page_free)(struct page___4 *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault___4 *);
	int (*memory_failure)(struct dev_pagemap___4 *, long unsigned int, long unsigned int, int);
};

struct socket_wq___4 {
	wait_queue_head_t wait;
	struct fasync_struct___4 *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
	long: 64;
};

struct proto_ops___4;

struct socket___4 {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file___4 *file;
	struct sock___4 *sk;
	const struct proto_ops___4 *ops;
	long: 64;
	long: 64;
	long: 64;
	struct socket_wq___4 wq;
};

typedef int (*sk_read_actor_t___4)(read_descriptor_t *, struct sk_buff___4 *, unsigned int, size_t);

typedef int (*skb_read_actor_t___4)(struct sock___4 *, struct sk_buff___4 *);

struct proto_ops___4 {
	int family;
	struct module___4 *owner;
	int (*release)(struct socket___4 *);
	int (*bind)(struct socket___4 *, struct sockaddr *, int);
	int (*connect)(struct socket___4 *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket___4 *, struct socket___4 *);
	int (*accept)(struct socket___4 *, struct socket___4 *, int, bool);
	int (*getname)(struct socket___4 *, struct sockaddr *, int);
	__poll_t (*poll)(struct file___4 *, struct socket___4 *, struct poll_table_struct___4 *);
	int (*ioctl)(struct socket___4 *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct socket___4 *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket___4 *, void *, bool, bool);
	int (*listen)(struct socket___4 *, int);
	int (*shutdown)(struct socket___4 *, int);
	int (*setsockopt)(struct socket___4 *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket___4 *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file___4 *, struct socket___4 *);
	int (*sendmsg)(struct socket___4 *, struct msghdr___4 *, size_t);
	int (*recvmsg)(struct socket___4 *, struct msghdr___4 *, size_t, int);
	int (*mmap)(struct file___4 *, struct socket___4 *, struct vm_area_struct___4 *);
	ssize_t (*sendpage)(struct socket___4 *, struct page___4 *, int, size_t, int);
	ssize_t (*splice_read)(struct socket___4 *, loff_t *, struct pipe_inode_info___4 *, size_t, unsigned int);
	int (*set_peek_off)(struct sock___4 *, int);
	int (*peek_len)(struct socket___4 *);
	int (*read_sock)(struct sock___4 *, read_descriptor_t *, sk_read_actor_t___4);
	int (*read_skb)(struct sock___4 *, skb_read_actor_t___4);
	int (*sendpage_locked)(struct sock___4 *, struct page___4 *, int, size_t, int);
	int (*sendmsg_locked)(struct sock___4 *, struct msghdr___4 *, size_t);
	int (*set_rcvlowat)(struct sock___4 *, int);
};

struct kernfs_elem_symlink___4 {
	struct kernfs_node___4 *target_kn;
};

struct kernfs_ops___4;

struct kernfs_elem_attr___4 {
	const struct kernfs_ops___4 *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node___4 *notify_next;
};

struct kernfs_node___4 {
	atomic_t count;
	atomic_t active;
	struct kernfs_node___4 *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink___4 symlink;
		struct kernfs_elem_attr___4 attr;
	};
	void *priv;
	u64 id;
	short unsigned int flags;
	umode_t mode;
	struct kernfs_iattrs *iattr;
};

struct kernfs_open_file___4;

struct kernfs_ops___4 {
	int (*open)(struct kernfs_open_file___4 *);
	void (*release)(struct kernfs_open_file___4 *);
	int (*seq_show)(struct seq_file___4 *, void *);
	void * (*seq_start)(struct seq_file___4 *, loff_t *);
	void * (*seq_next)(struct seq_file___4 *, void *, loff_t *);
	void (*seq_stop)(struct seq_file___4 *, void *);
	ssize_t (*read)(struct kernfs_open_file___4 *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file___4 *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file___4 *, struct poll_table_struct___4 *);
	int (*mmap)(struct kernfs_open_file___4 *, struct vm_area_struct___4 *);
};

struct kernfs_open_file___4 {
	struct kernfs_node___4 *kn;
	struct file___4 *file;
	struct seq_file___4 *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct___4 *vm_ops;
};

struct kobj_ns_type_operations___4 {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock___4 *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

struct bin_attribute___4 {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space___4 * (*f_mapping)();
	ssize_t (*read)(struct file___4 *, struct kobject___4 *, struct bin_attribute___4 *, char *, loff_t, size_t);
	ssize_t (*write)(struct file___4 *, struct kobject___4 *, struct bin_attribute___4 *, char *, loff_t, size_t);
	int (*mmap)(struct file___4 *, struct kobject___4 *, struct bin_attribute___4 *, struct vm_area_struct___4 *);
};

struct sysfs_ops___4 {
	ssize_t (*show)(struct kobject___4 *, struct attribute *, char *);
	ssize_t (*store)(struct kobject___4 *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops___4;

struct kset___4 {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject___4 kobj;
	const struct kset_uevent_ops___4 *uevent_ops;
};

struct kobj_type___4 {
	void (*release)(struct kobject___4 *);
	const struct sysfs_ops___4 *sysfs_ops;
	const struct attribute_group___4 **default_groups;
	const struct kobj_ns_type_operations___4 * (*child_ns_type)(struct kobject___4 *);
	const void * (*namespace)(struct kobject___4 *);
	void (*get_ownership)(struct kobject___4 *, kuid_t *, kgid_t *);
};

struct kset_uevent_ops___4 {
	int (* const filter)(struct kobject___4 *);
	const char * (* const name)(struct kobject___4 *);
	int (* const uevent)(struct kobject___4 *, struct kobj_uevent_env *);
};

struct dev_pm_ops___4 {
	int (*prepare)(struct device___4 *);
	void (*complete)(struct device___4 *);
	int (*suspend)(struct device___4 *);
	int (*resume)(struct device___4 *);
	int (*freeze)(struct device___4 *);
	int (*thaw)(struct device___4 *);
	int (*poweroff)(struct device___4 *);
	int (*restore)(struct device___4 *);
	int (*suspend_late)(struct device___4 *);
	int (*resume_early)(struct device___4 *);
	int (*freeze_late)(struct device___4 *);
	int (*thaw_early)(struct device___4 *);
	int (*poweroff_late)(struct device___4 *);
	int (*restore_early)(struct device___4 *);
	int (*suspend_noirq)(struct device___4 *);
	int (*resume_noirq)(struct device___4 *);
	int (*freeze_noirq)(struct device___4 *);
	int (*thaw_noirq)(struct device___4 *);
	int (*poweroff_noirq)(struct device___4 *);
	int (*restore_noirq)(struct device___4 *);
	int (*runtime_suspend)(struct device___4 *);
	int (*runtime_resume)(struct device___4 *);
	int (*runtime_idle)(struct device___4 *);
};

struct wakeup_source___4 {
	const char *name;
	int id;
	struct list_head entry;
	spinlock_t lock;
	struct wake_irq *wakeirq;
	struct timer_list timer;
	long unsigned int timer_expires;
	ktime_t total_time;
	ktime_t max_time;
	ktime_t last_time;
	ktime_t start_prevent_time;
	ktime_t prevent_sleep_time;
	long unsigned int event_count;
	long unsigned int active_count;
	long unsigned int relax_count;
	long unsigned int expire_count;
	long unsigned int wakeup_count;
	struct device___4 *dev;
	bool active: 1;
	bool autosleep_enabled: 1;
};

struct dev_pm_domain___4 {
	struct dev_pm_ops___4 ops;
	int (*start)(struct device___4 *);
	void (*detach)(struct device___4 *, bool);
	int (*activate)(struct device___4 *);
	void (*sync)(struct device___4 *);
	void (*dismiss)(struct device___4 *);
};

struct bus_type___4 {
	const char *name;
	const char *dev_name;
	struct device___4 *dev_root;
	const struct attribute_group___4 **bus_groups;
	const struct attribute_group___4 **dev_groups;
	const struct attribute_group___4 **drv_groups;
	int (*match)(struct device___4 *, struct device_driver___4 *);
	int (*uevent)(struct device___4 *, struct kobj_uevent_env *);
	int (*probe)(struct device___4 *);
	void (*sync_state)(struct device___4 *);
	void (*remove)(struct device___4 *);
	void (*shutdown)(struct device___4 *);
	int (*online)(struct device___4 *);
	int (*offline)(struct device___4 *);
	int (*suspend)(struct device___4 *, pm_message_t);
	int (*resume)(struct device___4 *);
	int (*num_vf)(struct device___4 *);
	int (*dma_configure)(struct device___4 *);
	void (*dma_cleanup)(struct device___4 *);
	const struct dev_pm_ops___4 *pm;
	const struct iommu_ops *iommu_ops;
	struct subsys_private *p;
	struct lock_class_key lock_key;
	bool need_parent_lock;
};

struct device_driver___4 {
	const char *name;
	struct bus_type___4 *bus;
	struct module___4 *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device___4 *);
	void (*sync_state)(struct device___4 *);
	int (*remove)(struct device___4 *);
	void (*shutdown)(struct device___4 *);
	int (*suspend)(struct device___4 *, pm_message_t);
	int (*resume)(struct device___4 *);
	const struct attribute_group___4 **groups;
	const struct attribute_group___4 **dev_groups;
	const struct dev_pm_ops___4 *pm;
	void (*coredump)(struct device___4 *);
	struct driver_private *p;
};

struct device_type___4 {
	const char *name;
	const struct attribute_group___4 **groups;
	int (*uevent)(struct device___4 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___4 *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device___4 *);
	const struct dev_pm_ops___4 *pm;
};

struct class___4 {
	const char *name;
	struct module___4 *owner;
	const struct attribute_group___4 **class_groups;
	const struct attribute_group___4 **dev_groups;
	struct kobject___4 *dev_kobj;
	int (*dev_uevent)(struct device___4 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___4 *, umode_t *);
	void (*class_release)(struct class___4 *);
	void (*dev_release)(struct device___4 *);
	int (*shutdown_pre)(struct device___4 *);
	const struct kobj_ns_type_operations___4 *ns_type;
	const void * (*namespace)(struct device___4 *);
	void (*get_ownership)(struct device___4 *, kuid_t *, kgid_t *);
	const struct dev_pm_ops___4 *pm;
	struct subsys_private *p;
};

struct kparam_array___4;

struct kernel_param___4 {
	const char *name;
	struct module___4 *mod;
	const struct kernel_param_ops___4 *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array___4 *arr;
	};
};

struct kparam_array___4 {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops___4 *ops;
	void *elem;
};

struct module_attribute___4 {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute___4 *, struct module_kobject___4 *, char *);
	ssize_t (*store)(struct module_attribute___4 *, struct module_kobject___4 *, const char *, size_t);
	void (*setup)(struct module___4 *, const char *);
	int (*test)(struct module___4 *);
	void (*free)(struct module___4 *);
};

struct fwnode_operations___4;

struct fwnode_handle___4 {
	struct fwnode_handle___4 *secondary;
	const struct fwnode_operations___4 *ops;
	struct device___4 *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

struct fwnode_reference_args___4;

struct fwnode_endpoint___4;

struct fwnode_operations___4 {
	struct fwnode_handle___4 * (*get)(struct fwnode_handle___4 *);
	void (*put)(struct fwnode_handle___4 *);
	bool (*device_is_available)(const struct fwnode_handle___4 *);
	const void * (*device_get_match_data)(const struct fwnode_handle___4 *, const struct device___4 *);
	bool (*device_dma_supported)(const struct fwnode_handle___4 *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle___4 *);
	bool (*property_present)(const struct fwnode_handle___4 *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle___4 *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle___4 *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle___4 *);
	const char * (*get_name_prefix)(const struct fwnode_handle___4 *);
	struct fwnode_handle___4 * (*get_parent)(const struct fwnode_handle___4 *);
	struct fwnode_handle___4 * (*get_next_child_node)(const struct fwnode_handle___4 *, struct fwnode_handle___4 *);
	struct fwnode_handle___4 * (*get_named_child_node)(const struct fwnode_handle___4 *, const char *);
	int (*get_reference_args)(const struct fwnode_handle___4 *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args___4 *);
	struct fwnode_handle___4 * (*graph_get_next_endpoint)(const struct fwnode_handle___4 *, struct fwnode_handle___4 *);
	struct fwnode_handle___4 * (*graph_get_remote_endpoint)(const struct fwnode_handle___4 *);
	struct fwnode_handle___4 * (*graph_get_port_parent)(struct fwnode_handle___4 *);
	int (*graph_parse_endpoint)(const struct fwnode_handle___4 *, struct fwnode_endpoint___4 *);
	void * (*iomap)(struct fwnode_handle___4 *, int);
	int (*irq_get)(const struct fwnode_handle___4 *, unsigned int);
	int (*add_links)(struct fwnode_handle___4 *);
};

struct fwnode_endpoint___4 {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle___4 *local_fwnode;
};

struct fwnode_reference_args___4 {
	struct fwnode_handle___4 *fwnode;
	unsigned int nargs;
	u64 args[8];
};

struct pipe_buf_operations___4;

struct pipe_buffer___4 {
	struct page___4 *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations___4 *ops;
	unsigned int flags;
	long unsigned int private;
};

struct pipe_buf_operations___4 {
	int (*confirm)(struct pipe_inode_info___4 *, struct pipe_buffer___4 *);
	void (*release)(struct pipe_inode_info___4 *, struct pipe_buffer___4 *);
	bool (*try_steal)(struct pipe_inode_info___4 *, struct pipe_buffer___4 *);
	bool (*get)(struct pipe_inode_info___4 *, struct pipe_buffer___4 *);
};

struct internal_dev {
	struct vport *vport;
};

struct kset___5;

struct kobj_type___5;

struct kernfs_node___5;

struct kobject___5 {
	const char *name;
	struct list_head entry;
	struct kobject___5 *parent;
	struct kset___5 *kset;
	const struct kobj_type___5 *ktype;
	struct kernfs_node___5 *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct module___5;

struct module_kobject___5 {
	struct kobject___5 kobj;
	struct module___5 *mod;
	struct kobject___5 *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct mod_tree_node___5 {
	struct module___5 *mod;
	struct latch_tree_node node;
};

struct module_layout___5 {
	void *base;
	unsigned int size;
	unsigned int text_size;
	unsigned int ro_size;
	unsigned int ro_after_init_size;
	struct mod_tree_node___5 mtn;
};

struct module_attribute___5;

struct kernel_param___5;

struct module___5 {
	enum module_state state;
	struct list_head list;
	char name[56];
	struct module_kobject___5 mkobj;
	struct module_attribute___5 *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject___5 *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param___5 *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool sig_ok;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	struct module_layout___5 core_layout;
	struct module_layout___5 init_layout;
	struct mod_arch_specific arch;
	long unsigned int taints;
	unsigned int num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map___3 *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	int num_static_call_sites;
	struct static_call_site *static_call_sites;
	int num_kunit_suites;
	struct kunit_suite **kunit_suites;
	bool klp;
	bool klp_alive;
	struct klp_modinfo *klp_info;
	unsigned int printk_index_size;
	struct pi_entry **printk_index_start;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
};

struct dentry___5;

struct super_block___5;

struct file_system_type___5 {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry___5 * (*mount)(struct file_system_type___5 *, int, const char *, void *);
	void (*kill_sb)(struct super_block___5 *);
	struct module___5 *owner;
	struct file_system_type___5 *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

struct kernel_param_ops___5 {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param___5 *);
	int (*get)(char *, const struct kernel_param___5 *);
	void (*free)(void *);
};

struct file___5;

struct kiocb___5;

struct iov_iter___5;

struct poll_table_struct___5;

struct vm_area_struct___5;

struct inode___5;

struct file_lock___5;

struct page___5;

struct pipe_inode_info___5;

struct seq_file___5;

struct file_operations___5 {
	struct module___5 *owner;
	loff_t (*llseek)(struct file___5 *, loff_t, int);
	ssize_t (*read)(struct file___5 *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file___5 *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb___5 *, struct iov_iter___5 *);
	ssize_t (*write_iter)(struct kiocb___5 *, struct iov_iter___5 *);
	int (*iopoll)(struct kiocb___5 *, struct io_comp_batch *, unsigned int);
	int (*iterate)(struct file___5 *, struct dir_context *);
	int (*iterate_shared)(struct file___5 *, struct dir_context *);
	__poll_t (*poll)(struct file___5 *, struct poll_table_struct___5 *);
	long int (*unlocked_ioctl)(struct file___5 *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file___5 *, unsigned int, long unsigned int);
	int (*mmap)(struct file___5 *, struct vm_area_struct___5 *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode___5 *, struct file___5 *);
	int (*flush)(struct file___5 *, fl_owner_t);
	int (*release)(struct inode___5 *, struct file___5 *);
	int (*fsync)(struct file___5 *, loff_t, loff_t, int);
	int (*fasync)(int, struct file___5 *, int);
	int (*lock)(struct file___5 *, int, struct file_lock___5 *);
	ssize_t (*sendpage)(struct file___5 *, struct page___5 *, int, size_t, loff_t *, int);
	long unsigned int (*get_unmapped_area)(struct file___5 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file___5 *, int, struct file_lock___5 *);
	ssize_t (*splice_write)(struct pipe_inode_info___5 *, struct file___5 *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file___5 *, loff_t *, struct pipe_inode_info___5 *, size_t, unsigned int);
	int (*setlease)(struct file___5 *, long int, struct file_lock___5 **, void **);
	long int (*fallocate)(struct file___5 *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file___5 *, struct file___5 *);
	ssize_t (*copy_file_range)(struct file___5 *, loff_t, struct file___5 *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file___5 *, loff_t, struct file___5 *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file___5 *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

struct page_frag___5 {
	struct page___5 *page;
	__u32 offset;
	__u32 size;
};

struct mm_struct___5;

struct nsproxy___5;

struct signal_struct___5;

struct bio_list___5;

struct backing_dev_info___5;

struct css_set___5;

struct mem_cgroup___5;

struct vm_struct___5;

struct task_struct___5 {
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct___5 *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	const struct sched_class *sched_class;
	struct rb_node core_node;
	long unsigned int core_cookie;
	unsigned int core_occupation;
	struct task_group *sched_task_group;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_statistics stats;
	struct hlist_head preempt_notifiers;
	unsigned int btrace_seq;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct___5 *mm;
	struct mm_struct___5 *active_mm;
	struct task_rss_stat rss_stat;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	unsigned int sched_psi_wake_requeue: 1;
	int: 28;
	unsigned int sched_remote_wakeup: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int in_user_fault: 1;
	unsigned int in_lru_fault: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_page_owner: 1;
	unsigned int in_eventfd: 1;
	unsigned int pasid_activated: 1;
	unsigned int reported_split_lock: 1;
	unsigned int in_thrashing: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct___5 *real_parent;
	struct task_struct___5 *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct___5 *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid___2 *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_group;
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	struct vtime vtime;
	atomic_t tick_dep_mask;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	struct posix_cputimers_work posix_cputimers_work;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy___5 *nsproxy;
	struct signal_struct___5 *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct audit_context *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct___5 *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	void *journal_info;
	struct bio_list___5 *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct backing_dev_info___5 *backing_dev_info;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	unsigned int psi_flags;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
	struct css_set___5 *cgroups;
	struct list_head cg_list;
	u32 closid;
	u32 rmid;
	struct robust_list_head *robust_list;
	struct compat_robust_list_head *compat_robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	struct perf_event_context *perf_event_ctxp[2];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	long unsigned int preempt_disable_ip;
	struct mempolicy *mempolicy;
	short int il_prev;
	short int pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	long unsigned int numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct numa_group *numa_group;
	long unsigned int *numa_faults;
	long unsigned int total_numa_faults;
	long unsigned int numa_faults_locality[3];
	long unsigned int numa_pages_migrated;
	struct rseq *rseq;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	struct tlbflush_unmap_batch tlb_ubc;
	union {
		refcount_t rcu_users;
		struct callback_head rcu;
	};
	struct pipe_inode_info___5 *splice_pipe;
	struct page_frag___5 task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	int latency_record_count;
	struct latency_record latency_record[32];
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	struct kunit *kunit_test;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace_recursion;
	struct mem_cgroup___5 *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup___5 *active_memcg;
	struct request_queue *throttle_queue;
	struct uprobe_task *utask;
	unsigned int sequential_io;
	unsigned int sequential_io_avg;
	struct kmap_ctrl kmap_ctrl;
	int pagefault_disabled;
	struct task_struct___5 *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct___5 *stack_vm_area;
	refcount_t stack_refcount;
	int patch_state;
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	void *mce_vaddr;
	__u64 mce_kflags;
	u64 mce_addr;
	__u64 mce_ripv: 1;
	__u64 mce_whole_page: 1;
	__u64 __mce_reserved: 62;
	struct callback_head mce_kill_me;
	int mce_count;
	struct llist_head kretprobe_instances;
	struct llist_head rethooks;
	struct callback_head l1d_flush_kill;
	union rv_task_monitor rv[1];
	struct thread_struct thread;
};

typedef struct page___5 *pgtable_t___5;

struct address_space___5;

struct page_pool___5;

struct dev_pagemap___5;

struct page___5 {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space___5 *mapping;
			long unsigned int index;
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool___5 *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			union {
				long unsigned int dma_addr_upper;
				atomic_long_t pp_frag_count;
			};
		};
		struct {
			long unsigned int compound_head;
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			atomic_t compound_pincount;
			unsigned int compound_nr;
		};
		struct {
			long unsigned int _compound_pad_1;
			long unsigned int _compound_pad_2;
			struct list_head deferred_list;
		};
		struct {
			long unsigned int _pt_pad_1;
			pgtable_t___5 pmd_huge_pte;
			long unsigned int _pt_pad_2;
			union {
				struct mm_struct___5 *pt_mm;
				atomic_t pt_frag_refcount;
			};
			spinlock_t ptl;
		};
		struct {
			struct dev_pagemap___5 *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	long unsigned int memcg_data;
};

struct mm_struct___5 {
	struct {
		struct maple_tree mm_mt;
		long unsigned int (*get_unmapped_area)(struct file___5 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int mmap_compat_base;
		long unsigned int mmap_compat_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		atomic_t mm_count;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[48];
		struct mm_rss_stat rss_stat;
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct___5 *owner;
		struct user_namespace *user_ns;
		struct file___5 *exe_file;
		struct mmu_notifier_subscriptions *notifier_subscriptions;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		atomic_t tlb_flush_batched;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		u32 pasid;
		long unsigned int ksm_merging_pages;
		long unsigned int ksm_rmap_items;
		struct {
			struct list_head list;
			long unsigned int bitmap;
			struct mem_cgroup___5 *memcg;
		} lru_gen;
	};
	long unsigned int cpu_bitmap[0];
};

struct vm_operations_struct___5;

struct vm_area_struct___5 {
	long unsigned int vm_start;
	long unsigned int vm_end;
	struct mm_struct___5 *vm_mm;
	pgprot_t vm_page_prot;
	long unsigned int vm_flags;
	union {
		struct {
			struct rb_node rb;
			long unsigned int rb_subtree_last;
		} shared;
		struct anon_vma_name *anon_name;
	};
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct___5 *vm_ops;
	long unsigned int vm_pgoff;
	struct file___5 *vm_file;
	void *vm_private_data;
	atomic_long_t swap_readahead_info;
	struct mempolicy *vm_policy;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

struct bin_attribute___5;

struct attribute_group___5 {
	const char *name;
	umode_t (*is_visible)(struct kobject___5 *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject___5 *, struct bin_attribute___5 *, int);
	struct attribute **attrs;
	struct bin_attribute___5 **bin_attrs;
};

struct seq_operations___5 {
	void * (*start)(struct seq_file___5 *, loff_t *);
	void (*stop)(struct seq_file___5 *, void *);
	void * (*next)(struct seq_file___5 *, void *, loff_t *);
	int (*show)(struct seq_file___5 *, void *);
};

struct core_state___5;

struct signal_struct___5 {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct___5 *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct___5 *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state___5 *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	int posix_timer_id;
	struct list_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid___2 *pids[4];
	atomic_t tick_dep_mask;
	struct pid___2 *tty_old_pgrp;
	int leader;
	struct tty_struct___2 *tty;
	struct autogroup *autogroup;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	unsigned int audit_tty;
	struct tty_audit_buf *tty_audit_buf;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct___5 *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct net___5;

struct nsproxy___5 {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net___5 *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct bio___5;

struct bio_list___5 {
	struct bio___5 *head;
	struct bio___5 *tail;
};

struct bdi_writeback___5 {
	struct backing_dev_info___5 *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	long unsigned int dirty_sleep;
	struct list_head bdi_node;
	struct percpu_ref refcnt;
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css;
	struct cgroup_subsys_state *blkcg_css;
	struct list_head memcg_node;
	struct list_head blkcg_node;
	struct list_head b_attached;
	struct list_head offline_node;
	union {
		struct work_struct release_work;
		struct callback_head rcu;
	};
};

struct device___5;

struct backing_dev_info___5 {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	struct bdi_writeback___5 wb;
	struct list_head wb_list;
	struct xarray cgwb_tree;
	struct mutex cgwb_release_mutex;
	struct rw_semaphore wb_switch_rwsem;
	wait_queue_head_t wb_waitq;
	struct device___5 *dev;
	char dev_name[64];
	struct device___5 *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry___5 *debug_dir;
};

struct cgroup___5;

struct css_set___5 {
	struct cgroup_subsys_state *subsys[13];
	refcount_t refcount;
	struct css_set___5 *dom_cset;
	struct cgroup___5 *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[13];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_src_preload_node;
	struct list_head mg_dst_preload_node;
	struct list_head mg_node;
	struct cgroup___5 *mg_src_cgrp;
	struct cgroup___5 *mg_dst_cgrp;
	struct css_set___5 *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
};

struct fasync_struct___5;

struct pipe_buffer___5;

struct pipe_inode_info___5 {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	bool note_loss;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	struct page___5 *tmp_page;
	struct fasync_struct___5 *fasync_readers;
	struct fasync_struct___5 *fasync_writers;
	struct pipe_buffer___5 *bufs;
	struct user_struct *user;
	struct watch_queue *watch_queue;
};

struct mem_cgroup___5 {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct page_counter memory;
	union {
		struct page_counter swap;
		struct page_counter memsw;
	};
	struct page_counter kmem;
	struct page_counter tcpmem;
	struct work_struct high_work;
	long unsigned int zswap_max;
	long unsigned int soft_limit;
	struct vmpressure vmpressure;
	bool oom_group;
	bool oom_lock;
	int under_oom;
	int swappiness;
	int oom_kill_disable;
	struct cgroup_file events_file;
	struct cgroup_file events_local_file;
	struct cgroup_file swap_events_file;
	struct mutex thresholds_lock;
	struct mem_cgroup_thresholds thresholds;
	struct mem_cgroup_thresholds memsw_thresholds;
	struct list_head oom_notify;
	long unsigned int move_charge_at_immigrate;
	spinlock_t move_lock;
	long unsigned int move_lock_flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct memcg_vmstats *vmstats;
	atomic_long_t memory_events[9];
	atomic_long_t memory_events_local[9];
	long unsigned int socket_pressure;
	bool tcpmem_active;
	int tcpmem_pressure;
	int kmemcg_id;
	struct obj_cgroup *objcg;
	struct list_head objcg_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	atomic_t moving_account;
	struct task_struct___5 *move_lock_task;
	struct memcg_vmstats_percpu *vmstats_percpu;
	struct list_head cgwb_list;
	struct wb_domain cgwb_domain;
	struct memcg_cgwb_frn cgwb_frn[4];
	struct list_head event_list;
	spinlock_t event_list_lock;
	struct deferred_split deferred_split_queue;
	struct lru_gen_mm_list mm_list;
	struct mem_cgroup_per_node *nodeinfo[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct vm_struct___5 {
	struct vm_struct___5 *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page___5 **pages;
	unsigned int page_order;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

struct address_space_operations___5;

struct address_space___5 {
	struct inode___5 *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	struct rw_semaphore i_mmap_rwsem;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations___5 *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t private_lock;
	struct list_head private_list;
	void *private_data;
};

struct page_pool_params___5 {
	unsigned int flags;
	unsigned int order;
	unsigned int pool_size;
	int nid;
	struct device___5 *dev;
	enum dma_data_direction dma_dir;
	unsigned int max_len;
	unsigned int offset;
	void (*init_callback)(struct page___5 *, void *);
	void *init_arg;
};

struct pp_alloc_cache___5 {
	u32 count;
	struct page___5 *cache[128];
};

struct page_pool___5 {
	struct page_pool_params___5 p;
	struct delayed_work release_dw;
	void (*disconnect)(void *);
	long unsigned int defer_start;
	long unsigned int defer_warn;
	u32 pages_state_hold_cnt;
	unsigned int frag_offset;
	struct page___5 *frag_page;
	long int frag_users;
	u32 xdp_mem_id;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct pp_alloc_cache___5 alloc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct ptr_ring ring;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct dev_pagemap_ops___5;

struct dev_pagemap___5 {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops___5 *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct range ranges[0];
	};
};

struct folio___5 {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space___5 *mapping;
			long unsigned int index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page___5 page;
	};
	long unsigned int _flags_1;
	long unsigned int __head;
	unsigned char _folio_dtor;
	unsigned char _folio_order;
	atomic_t _total_mapcount;
	atomic_t _pincount;
	unsigned int _folio_nr_pages;
};

struct vfsmount___5;

struct path___5 {
	struct vfsmount___5 *mnt;
	struct dentry___5 *dentry;
};

struct file___5 {
	union {
		struct llist_node f_llist;
		struct callback_head f_rcuhead;
		unsigned int f_iocb_flags;
	};
	struct path___5 f_path;
	struct inode___5 *f_inode;
	const struct file_operations___5 *f_op;
	spinlock_t f_lock;
	atomic_long_t f_count;
	unsigned int f_flags;
	fmode_t f_mode;
	struct mutex f_pos_lock;
	loff_t f_pos;
	struct fown_struct___2 f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	u64 f_version;
	void *f_security;
	void *private_data;
	struct hlist_head *f_ep;
	struct address_space___5 *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};

struct vm_fault___5;

struct vm_operations_struct___5 {
	void (*open)(struct vm_area_struct___5 *);
	void (*close)(struct vm_area_struct___5 *);
	int (*may_split)(struct vm_area_struct___5 *, long unsigned int);
	int (*mremap)(struct vm_area_struct___5 *);
	int (*mprotect)(struct vm_area_struct___5 *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault___5 *);
	vm_fault_t (*huge_fault)(struct vm_fault___5 *, enum page_entry_size);
	vm_fault_t (*map_pages)(struct vm_fault___5 *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct___5 *);
	vm_fault_t (*page_mkwrite)(struct vm_fault___5 *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault___5 *);
	int (*access)(struct vm_area_struct___5 *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct___5 *);
	int (*set_policy)(struct vm_area_struct___5 *, struct mempolicy *);
	struct mempolicy * (*get_policy)(struct vm_area_struct___5 *, long unsigned int);
	struct page___5 * (*find_special_page)(struct vm_area_struct___5 *, long unsigned int);
};

struct vm_fault___5 {
	const struct {
		struct vm_area_struct___5 *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page___5 *cow_page;
	struct page___5 *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t___5 prealloc_pte;
};

struct bio_vec___5 {
	struct page___5 *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct iov_iter___5 {
	u8 iter_type;
	bool nofault;
	bool data_source;
	bool user_backed;
	union {
		size_t iov_offset;
		int last_offset;
	};
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec___5 *bvec;
		struct xarray *xarray;
		struct pipe_inode_info___5 *pipe;
		void *ubuf;
	};
	union {
		long unsigned int nr_segs;
		struct {
			unsigned int head;
			unsigned int start_head;
		};
		loff_t xarray_start;
	};
};

struct ubuf_info___5;

struct sock___5;

struct sk_buff___5;

struct msghdr___5 {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter___5 msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb___5 *msg_iocb;
	struct ubuf_info___5 *msg_ubuf;
	int (*sg_from_iter)(struct sock___5 *, struct sk_buff___5 *, struct iov_iter___5 *, size_t);
};

struct kiocb___5 {
	struct file___5 *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb___5 *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	struct wait_page_queue *ki_waitq;
};

struct ubuf_info___5 {
	void (*callback)(struct sk_buff___5 *, struct ubuf_info___5 *, bool);
	refcount_t refcnt;
	u8 flags;
};

struct sk_buff_list___5 {
	struct sk_buff___5 *next;
	struct sk_buff___5 *prev;
};

struct sk_buff_head___5 {
	union {
		struct {
			struct sk_buff___5 *next;
			struct sk_buff___5 *prev;
		};
		struct sk_buff_list___5 list;
	};
	__u32 qlen;
	spinlock_t lock;
};

struct dst_entry___3;

struct socket___5;

struct net_device___5;

struct sock___5 {
	struct sock_common __sk_common;
	struct dst_entry___3 *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	socket_lock_t sk_lock;
	atomic_t sk_drops;
	int sk_rcvlowat;
	struct sk_buff_head___5 sk_error_queue;
	struct sk_buff_head___5 sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	int sk_forward_alloc;
	u32 sk_reserved_mem;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	int sk_rcvbuf;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	struct xfrm_policy *sk_policy[2];
	struct dst_entry___3 *sk_dst_cache;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head___5 sk_write_queue;
	__s32 sk_peek_off;
	int sk_write_pending;
	__u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	long int sk_sndtimeo;
	struct timer_list sk_timer;
	__u32 sk_priority;
	__u32 sk_mark;
	long unsigned int sk_pacing_rate;
	long unsigned int sk_max_pacing_rate;
	struct page_frag___5 sk_frag;
	netdev_features_t sk_route_caps;
	int sk_gso_type;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	__u32 sk_txhash;
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_userlocks: 4;
	u8 sk_pacing_shift;
	u16 sk_type;
	u16 sk_protocol;
	u16 sk_gso_max_segs;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	u8 sk_txrehash;
	u8 sk_prefer_busy_poll;
	u16 sk_busy_poll_budget;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid___2 *sk_peer_pid;
	const struct cred *sk_peer_cred;
	long int sk_rcvtimeo;
	ktime_t sk_stamp;
	u16 sk_tsflags;
	u8 sk_shutdown;
	atomic_t sk_tskey;
	atomic_t sk_zckey;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	struct socket___5 *sk_socket;
	void *sk_user_data;
	void *sk_security;
	struct sock_cgroup_data sk_cgrp_data;
	struct mem_cgroup___5 *sk_memcg;
	void (*sk_state_change)(struct sock___5 *);
	void (*sk_data_ready)(struct sock___5 *);
	void (*sk_write_space)(struct sock___5 *);
	void (*sk_error_report)(struct sock___5 *);
	int (*sk_backlog_rcv)(struct sock___5 *, struct sk_buff___5 *);
	struct sk_buff___5 * (*sk_validate_xmit_skb)(struct sock___5 *, struct net_device___5 *, struct sk_buff___5 *);
	void (*sk_destruct)(struct sock___5 *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
	struct hlist_node sk_bind2_node;
};

struct sk_buff___5 {
	union {
		struct {
			struct sk_buff___5 *next;
			struct sk_buff___5 *prev;
			union {
				struct net_device___5 *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	union {
		struct sock___5 *sk;
		int ip_defrag_offset;
	};
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff___5 *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};

struct inet_frags___3;

struct fqdir___4 {
	long int high_thresh;
	long int low_thresh;
	int timeout;
	int max_dist;
	struct inet_frags___3 *f;
	struct net___5 *net;
	bool dead;
	long: 56;
	long: 64;
	long: 64;
	struct rhashtable rhashtable;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t mem;
	struct work_struct destroy_work;
	struct llist_node free_list;
	long: 64;
	long: 64;
};

struct inet_frag_queue___3;

struct inet_frags___3 {
	unsigned int qsize;
	void (*constructor)(struct inet_frag_queue___3 *, const void *);
	void (*destructor)(struct inet_frag_queue___3 *);
	void (*frag_expire)(struct timer_list *);
	struct kmem_cache *frags_cachep;
	const char *frags_cache_name;
	struct rhashtable_params rhash_params;
	refcount_t refcnt;
	struct completion completion;
};

struct ip_ra_chain___3;

struct fib_rules_ops___3;

struct fib_notifier_ops___3;

struct netns_ipv4___3 {
	struct inet_timewait_death_row tcp_death_row;
	struct ctl_table_header *forw_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *ipv4_hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *xfrm4_hdr;
	struct ipv4_devconf *devconf_all;
	struct ipv4_devconf *devconf_dflt;
	struct ip_ra_chain___3 *ra_chain;
	struct mutex ra_mutex;
	struct fib_rules_ops___3 *rules_ops;
	struct fib_table *fib_main;
	struct fib_table *fib_default;
	unsigned int fib_rules_require_fldissect;
	bool fib_has_custom_rules;
	bool fib_has_custom_local_routes;
	bool fib_offload_disabled;
	atomic_t fib_num_tclassid_users;
	struct hlist_head *fib_table_hash;
	struct sock___5 *fibnl;
	struct sock___5 *mc_autojoin_sk;
	struct inet_peer_base *peers;
	struct fqdir___4 *fqdir;
	u8 sysctl_icmp_echo_ignore_all;
	u8 sysctl_icmp_echo_enable_probe;
	u8 sysctl_icmp_echo_ignore_broadcasts;
	u8 sysctl_icmp_ignore_bogus_error_responses;
	u8 sysctl_icmp_errors_use_inbound_ifaddr;
	int sysctl_icmp_ratelimit;
	int sysctl_icmp_ratemask;
	u32 ip_rt_min_pmtu;
	int ip_rt_mtu_expires;
	int ip_rt_min_advmss;
	struct local_ports ip_local_ports;
	u8 sysctl_tcp_ecn;
	u8 sysctl_tcp_ecn_fallback;
	u8 sysctl_ip_default_ttl;
	u8 sysctl_ip_no_pmtu_disc;
	u8 sysctl_ip_fwd_use_pmtu;
	u8 sysctl_ip_fwd_update_priority;
	u8 sysctl_ip_nonlocal_bind;
	u8 sysctl_ip_autobind_reuse;
	u8 sysctl_ip_dynaddr;
	u8 sysctl_ip_early_demux;
	u8 sysctl_raw_l3mdev_accept;
	u8 sysctl_tcp_early_demux;
	u8 sysctl_udp_early_demux;
	u8 sysctl_nexthop_compat_mode;
	u8 sysctl_fwmark_reflect;
	u8 sysctl_tcp_fwmark_accept;
	u8 sysctl_tcp_l3mdev_accept;
	u8 sysctl_tcp_mtu_probing;
	int sysctl_tcp_mtu_probe_floor;
	int sysctl_tcp_base_mss;
	int sysctl_tcp_min_snd_mss;
	int sysctl_tcp_probe_threshold;
	u32 sysctl_tcp_probe_interval;
	int sysctl_tcp_keepalive_time;
	int sysctl_tcp_keepalive_intvl;
	u8 sysctl_tcp_keepalive_probes;
	u8 sysctl_tcp_syn_retries;
	u8 sysctl_tcp_synack_retries;
	u8 sysctl_tcp_syncookies;
	u8 sysctl_tcp_migrate_req;
	u8 sysctl_tcp_comp_sack_nr;
	int sysctl_tcp_reordering;
	u8 sysctl_tcp_retries1;
	u8 sysctl_tcp_retries2;
	u8 sysctl_tcp_orphan_retries;
	u8 sysctl_tcp_tw_reuse;
	int sysctl_tcp_fin_timeout;
	unsigned int sysctl_tcp_notsent_lowat;
	u8 sysctl_tcp_sack;
	u8 sysctl_tcp_window_scaling;
	u8 sysctl_tcp_timestamps;
	u8 sysctl_tcp_early_retrans;
	u8 sysctl_tcp_recovery;
	u8 sysctl_tcp_thin_linear_timeouts;
	u8 sysctl_tcp_slow_start_after_idle;
	u8 sysctl_tcp_retrans_collapse;
	u8 sysctl_tcp_stdurg;
	u8 sysctl_tcp_rfc1337;
	u8 sysctl_tcp_abort_on_overflow;
	u8 sysctl_tcp_fack;
	int sysctl_tcp_max_reordering;
	int sysctl_tcp_adv_win_scale;
	u8 sysctl_tcp_dsack;
	u8 sysctl_tcp_app_win;
	u8 sysctl_tcp_frto;
	u8 sysctl_tcp_nometrics_save;
	u8 sysctl_tcp_no_ssthresh_metrics_save;
	u8 sysctl_tcp_moderate_rcvbuf;
	u8 sysctl_tcp_tso_win_divisor;
	u8 sysctl_tcp_workaround_signed_windows;
	int sysctl_tcp_limit_output_bytes;
	int sysctl_tcp_challenge_ack_limit;
	int sysctl_tcp_min_rtt_wlen;
	u8 sysctl_tcp_min_tso_segs;
	u8 sysctl_tcp_tso_rtt_log;
	u8 sysctl_tcp_autocorking;
	u8 sysctl_tcp_reflect_tos;
	int sysctl_tcp_invalid_ratelimit;
	int sysctl_tcp_pacing_ss_ratio;
	int sysctl_tcp_pacing_ca_ratio;
	int sysctl_tcp_wmem[3];
	int sysctl_tcp_rmem[3];
	unsigned int sysctl_tcp_child_ehash_entries;
	long unsigned int sysctl_tcp_comp_sack_delay_ns;
	long unsigned int sysctl_tcp_comp_sack_slack_ns;
	int sysctl_max_syn_backlog;
	int sysctl_tcp_fastopen;
	const struct tcp_congestion_ops *tcp_congestion_control;
	struct tcp_fastopen_context *tcp_fastopen_ctx;
	unsigned int sysctl_tcp_fastopen_blackhole_timeout;
	atomic_t tfo_active_disable_times;
	long unsigned int tfo_active_disable_stamp;
	u32 tcp_challenge_timestamp;
	u32 tcp_challenge_count;
	int sysctl_udp_wmem_min;
	int sysctl_udp_rmem_min;
	u8 sysctl_fib_notify_on_flag_change;
	u8 sysctl_udp_l3mdev_accept;
	u8 sysctl_igmp_llm_reports;
	int sysctl_igmp_max_memberships;
	int sysctl_igmp_max_msf;
	int sysctl_igmp_qrv;
	struct ping_group_range ping_group_range;
	atomic_t dev_addr_genid;
	long unsigned int *sysctl_local_reserved_ports;
	int sysctl_ip_prot_sock;
	struct list_head mr_tables;
	struct fib_rules_ops___3 *mr_rules_ops;
	u32 sysctl_fib_multipath_hash_fields;
	u8 sysctl_fib_multipath_use_neigh;
	u8 sysctl_fib_multipath_hash_policy;
	struct fib_notifier_ops___3 *notifier_ops;
	unsigned int fib_seq;
	struct fib_notifier_ops___3 *ipmr_notifier_ops;
	unsigned int ipmr_seq;
	atomic_t rt_genid;
	siphash_key_t ip_id_key;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct neighbour___3;

struct dst_ops___3 {
	short unsigned int family;
	unsigned int gc_thresh;
	int (*gc)(struct dst_ops___3 *);
	struct dst_entry___3 * (*check)(struct dst_entry___3 *, __u32);
	unsigned int (*default_advmss)(const struct dst_entry___3 *);
	unsigned int (*mtu)(const struct dst_entry___3 *);
	u32 * (*cow_metrics)(struct dst_entry___3 *, long unsigned int);
	void (*destroy)(struct dst_entry___3 *);
	void (*ifdown)(struct dst_entry___3 *, struct net_device___5 *, int);
	struct dst_entry___3 * (*negative_advice)(struct dst_entry___3 *);
	void (*link_failure)(struct sk_buff___5 *);
	void (*update_pmtu)(struct dst_entry___3 *, struct sock___5 *, struct sk_buff___5 *, u32, bool);
	void (*redirect)(struct dst_entry___3 *, struct sock___5 *, struct sk_buff___5 *);
	int (*local_out)(struct net___5 *, struct sock___5 *, struct sk_buff___5 *);
	struct neighbour___3 * (*neigh_lookup)(const struct dst_entry___3 *, struct sk_buff___5 *, const void *);
	void (*confirm_neigh)(const struct dst_entry___3 *, const void *);
	struct kmem_cache *kmem_cachep;
	struct percpu_counter pcpuc_entries;
	long: 64;
	long: 64;
	long: 64;
};

struct fib6_info___3;

struct rt6_info___3;

struct fib6_table___3;

struct netns_ipv6___3 {
	struct dst_ops___3 ip6_dst_ops;
	struct netns_sysctl_ipv6 sysctl;
	struct ipv6_devconf *devconf_all;
	struct ipv6_devconf *devconf_dflt;
	struct inet_peer_base *peers;
	struct fqdir___4 *fqdir;
	struct fib6_info___3 *fib6_null_entry;
	struct rt6_info___3 *ip6_null_entry;
	struct rt6_statistics *rt6_stats;
	struct timer_list ip6_fib_timer;
	struct hlist_head *fib_table_hash;
	struct fib6_table___3 *fib6_main_tbl;
	struct list_head fib6_walkers;
	rwlock_t fib6_walker_lock;
	spinlock_t fib6_gc_lock;
	atomic_t ip6_rt_gc_expire;
	long unsigned int ip6_rt_last_gc;
	unsigned char flowlabel_has_excl;
	bool fib6_has_custom_rules;
	unsigned int fib6_rules_require_fldissect;
	unsigned int fib6_routes_require_src;
	struct rt6_info___3 *ip6_prohibit_entry;
	struct rt6_info___3 *ip6_blk_hole_entry;
	struct fib6_table___3 *fib6_local_tbl;
	struct fib_rules_ops___3 *fib6_rules_ops;
	struct sock___5 *ndisc_sk;
	struct sock___5 *tcp_sk;
	struct sock___5 *igmp_sk;
	struct sock___5 *mc_autojoin_sk;
	struct hlist_head *inet6_addr_lst;
	spinlock_t addrconf_hash_lock;
	struct delayed_work addr_chk_work;
	struct list_head mr6_tables;
	struct fib_rules_ops___3 *mr6_rules_ops;
	atomic_t dev_addr_genid;
	atomic_t fib6_sernum;
	struct seg6_pernet_data *seg6_data;
	struct fib_notifier_ops___3 *notifier_ops;
	struct fib_notifier_ops___3 *ip6mr_notifier_ops;
	unsigned int ipmr_seq;
	struct {
		struct hlist_head head;
		spinlock_t lock;
		u32 seq;
	} ip6addrlbl_table;
	struct ioam6_pernet_data *ioam6_data;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct netns_ieee802154_lowpan___3 {
	struct netns_sysctl_lowpan sysctl;
	struct fqdir___4 *fqdir;
};

struct netns_sctp___3 {
	struct sctp_mib *sctp_statistics;
	struct proc_dir_entry *proc_net_sctp;
	struct ctl_table_header *sysctl_header;
	struct sock___5 *ctl_sock;
	struct sock___5 *udp4_sock;
	struct sock___5 *udp6_sock;
	int udp_port;
	int encap_port;
	struct list_head local_addr_list;
	struct list_head addr_waitq;
	struct timer_list addr_wq_timer;
	struct list_head auto_asconf_splist;
	spinlock_t addr_wq_lock;
	spinlock_t local_addr_lock;
	unsigned int rto_initial;
	unsigned int rto_min;
	unsigned int rto_max;
	int rto_alpha;
	int rto_beta;
	int max_burst;
	int cookie_preserve_enable;
	char *sctp_hmac_alg;
	unsigned int valid_cookie_life;
	unsigned int sack_timeout;
	unsigned int hb_interval;
	unsigned int probe_interval;
	int max_retrans_association;
	int max_retrans_path;
	int max_retrans_init;
	int pf_retrans;
	int ps_retrans;
	int pf_enable;
	int pf_expose;
	int sndbuf_policy;
	int rcvbuf_policy;
	int default_auto_asconf;
	int addip_enable;
	int addip_noauth;
	int prsctp_enable;
	int reconf_enable;
	int auth_enable;
	int intl_enable;
	int ecn_enable;
	int scope_policy;
	int rwnd_upd_shift;
	long unsigned int max_autoclose;
};

struct nf_hook_entries___2;

struct netns_nf___2 {
	struct proc_dir_entry *proc_netfilter;
	const struct nf_logger *nf_loggers[11];
	struct ctl_table_header *nf_log_dir_header;
	struct nf_hook_entries___2 *hooks_ipv4[5];
	struct nf_hook_entries___2 *hooks_ipv6[5];
	struct nf_hook_entries___2 *hooks_arp[3];
	struct nf_hook_entries___2 *hooks_bridge[5];
	unsigned int defrag_ipv4_users;
	unsigned int defrag_ipv6_users;
};

struct netns_xfrm___3 {
	struct list_head state_all;
	struct hlist_head *state_bydst;
	struct hlist_head *state_bysrc;
	struct hlist_head *state_byspi;
	struct hlist_head *state_byseq;
	unsigned int state_hmask;
	unsigned int state_num;
	struct work_struct state_hash_work;
	struct list_head policy_all;
	struct hlist_head *policy_byidx;
	unsigned int policy_idx_hmask;
	struct hlist_head policy_inexact[3];
	struct xfrm_policy_hash policy_bydst[3];
	unsigned int policy_count[6];
	struct work_struct policy_hash_work;
	struct xfrm_policy_hthresh policy_hthresh;
	struct list_head inexact_bins;
	struct sock___5 *nlsk;
	struct sock___5 *nlsk_stash;
	u32 sysctl_aevent_etime;
	u32 sysctl_aevent_rseqth;
	int sysctl_larval_drop;
	u32 sysctl_acq_expires;
	u8 policy_default[3];
	struct ctl_table_header *sysctl_hdr;
	long: 64;
	long: 64;
	long: 64;
	struct dst_ops___3 xfrm4_dst_ops;
	struct dst_ops___3 xfrm6_dst_ops;
	spinlock_t xfrm_state_lock;
	seqcount_spinlock_t xfrm_state_hash_generation;
	seqcount_spinlock_t xfrm_policy_hash_generation;
	spinlock_t xfrm_policy_lock;
	struct mutex xfrm_cfg_mutex;
	long: 64;
	long: 64;
};

struct net___5 {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	atomic_t dev_unreg_count;
	unsigned int dev_base_seq;
	int ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node cleanup_list;
	struct key_tag *key_domain;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
	struct sock___5 *rtnl;
	struct sock___5 *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device___5 *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_ipv4___3 ipv4;
	struct netns_ipv6___3 ipv6;
	struct netns_ieee802154_lowpan___3 ieee802154_lowpan;
	struct netns_sctp___3 sctp;
	struct netns_nf___2 nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct netns_ft ft;
	struct sk_buff_head___5 wext_nlevents;
	struct net_generic *gen;
	struct netns_bpf bpf;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_xfrm___3 xfrm;
	u64 net_cookie;
	struct netns_ipvs *ipvs;
	struct netns_mpls mpls;
	struct netns_can can;
	struct netns_xdp xdp;
	struct netns_mctp mctp;
	struct sock___5 *crypto_nlsk;
	struct sock___5 *diag_nlsk;
	struct netns_smc smc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct inet_frag_queue___3 {
	struct rhash_head node;
	union {
		struct frag_v4_compare_key v4;
		struct frag_v6_compare_key v6;
	} key;
	struct timer_list timer;
	spinlock_t lock;
	refcount_t refcnt;
	struct rb_root rb_fragments;
	struct sk_buff___5 *fragments_tail;
	struct sk_buff___5 *last_run_head;
	ktime_t stamp;
	int len;
	int meat;
	u8 mono_delivery_time;
	__u8 flags;
	u16 max_size;
	struct fqdir___4 *fqdir;
	struct callback_head rcu;
};

struct ip_ra_chain___3 {
	struct ip_ra_chain___3 *next;
	struct sock___5 *sk;
	union {
		void (*destructor)(struct sock *);
		struct sock *saved_sk;
	};
	struct callback_head rcu;
};

struct fib_rules_ops___3 {
	int family;
	struct list_head list;
	int rule_size;
	int addr_size;
	int unresolved_rules;
	int nr_goto_rules;
	unsigned int fib_rules_seq;
	int (*action)(struct fib_rule *, struct flowi *, int, struct fib_lookup_arg *);
	bool (*suppress)(struct fib_rule *, int, struct fib_lookup_arg *);
	int (*match)(struct fib_rule *, struct flowi *, int);
	int (*configure)(struct fib_rule *, struct sk_buff___5 *, struct fib_rule_hdr *, struct nlattr **, struct netlink_ext_ack *);
	int (*delete)(struct fib_rule *);
	int (*compare)(struct fib_rule *, struct fib_rule_hdr *, struct nlattr **);
	int (*fill)(struct fib_rule *, struct sk_buff___5 *, struct fib_rule_hdr *);
	size_t (*nlmsg_payload)(struct fib_rule *);
	void (*flush_cache)(struct fib_rules_ops___3 *);
	int nlgroup;
	struct list_head rules_list;
	struct module___5 *owner;
	struct net___5 *fro_net;
	struct callback_head rcu;
};

struct fib_notifier_ops___3 {
	int family;
	struct list_head list;
	unsigned int (*fib_seq_read)(struct net___5 *);
	int (*fib_dump)(struct net___5 *, struct notifier_block *, struct netlink_ext_ack *);
	struct module___5 *owner;
	struct callback_head rcu;
};

struct lruvec___5;

struct lru_gen_mm_walk___5 {
	struct lruvec___5 *lruvec;
	long unsigned int max_seq;
	long unsigned int next_addr;
	int nr_pages[40];
	int mm_stats[6];
	int batched;
	bool can_swap;
	bool force_scan;
};

struct pglist_data___5;

struct lruvec___5 {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
	struct lru_gen_struct lrugen;
	struct lru_gen_mm_state mm_state;
	struct pglist_data___5 *pgdat;
};

struct zone___5 {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long int lowmem_reserve[5];
	int node;
	struct pglist_data___5 *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high;
	int pageset_batch;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	long unsigned int present_early_pages;
	long unsigned int cma_pages;
	const char *name;
	long unsigned int nr_isolate_pageblock;
	seqlock_t span_seqlock;
	int initialized;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct free_area free_area[11];
	long unsigned int flags;
	spinlock_t lock;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int percpu_drift_mark;
	long unsigned int compact_cached_free_pfn;
	long unsigned int compact_cached_migrate_pfn[2];
	long unsigned int compact_init_migrate_pfn;
	long unsigned int compact_init_free_pfn;
	unsigned int compact_considered;
	unsigned int compact_defer_shift;
	int compact_order_failed;
	bool compact_blockskip_flush;
	bool contiguous;
	short: 16;
	struct cacheline_padding _pad3_;
	atomic_long_t vm_stat[11];
	atomic_long_t vm_numa_event[6];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct zoneref___5 {
	struct zone___5 *zone;
	int zone_idx;
};

struct zonelist___5 {
	struct zoneref___5 _zonerefs[5121];
};

struct pglist_data___5 {
	struct zone___5 node_zones[5];
	struct zonelist___5 node_zonelists[2];
	int nr_zones;
	spinlock_t node_size_lock;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct mutex kswapd_lock;
	struct task_struct___5 *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct___5 *kcompactd;
	bool proactive_compact_trigger;
	long unsigned int totalreserve_pages;
	long unsigned int min_unmapped_pages;
	long unsigned int min_slab_pages;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct deferred_split deferred_split_queue;
	unsigned int nbp_rl_start;
	long unsigned int nbp_rl_nr_cand;
	unsigned int nbp_threshold;
	unsigned int nbp_th_start;
	long unsigned int nbp_th_nr_cand;
	struct lruvec___5 __lruvec;
	long unsigned int flags;
	struct lru_gen_mm_walk___5 mm_walk;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[43];
	struct memory_tier *memtier;
	long: 64;
	long: 64;
	long: 64;
};

struct dst_entry___3 {
	struct net_device___5 *dev;
	struct dst_ops___3 *ops;
	long unsigned int _metrics;
	long unsigned int expires;
	struct xfrm_state *xfrm;
	int (*input)(struct sk_buff___5 *);
	int (*output)(struct net___5 *, struct sock___5 *, struct sk_buff___5 *);
	short unsigned int flags;
	short int obsolete;
	short unsigned int header_len;
	short unsigned int trailer_len;
	atomic_t __refcnt;
	int __use;
	long unsigned int lastuse;
	struct lwtunnel_state *lwtstate;
	struct callback_head callback_head;
	short int error;
	short int __pad;
	__u32 tclassid;
	netdevice_tracker dev_tracker;
};

typedef rx_handler_result_t rx_handler_func_t___5(struct sk_buff___5 **);

struct wakeup_source___5;

struct dev_pm_info___5 {
	pm_message_t power_state;
	unsigned int can_wakeup: 1;
	unsigned int async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	struct list_head entry;
	struct completion completion;
	struct wakeup_source___5 *wakeup;
	bool wakeup_path: 1;
	bool syscore: 1;
	bool no_pm_callbacks: 1;
	unsigned int must_resume: 1;
	unsigned int may_skip_resume: 1;
	struct hrtimer suspend_timer;
	u64 timer_expires;
	struct work_struct work;
	wait_queue_head_t wait_queue;
	struct wake_irq *wakeirq;
	atomic_t usage_count;
	atomic_t child_count;
	unsigned int disable_depth: 3;
	unsigned int idle_notification: 1;
	unsigned int request_pending: 1;
	unsigned int deferred_resume: 1;
	unsigned int needs_force_resume: 1;
	unsigned int runtime_auto: 1;
	bool ignore_children: 1;
	unsigned int no_callbacks: 1;
	unsigned int irq_safe: 1;
	unsigned int use_autosuspend: 1;
	unsigned int timer_autosuspends: 1;
	unsigned int memalloc_noio: 1;
	unsigned int links_count;
	enum rpm_request request;
	enum rpm_status runtime_status;
	enum rpm_status last_status;
	int runtime_error;
	int autosuspend_delay;
	u64 last_busy;
	u64 active_time;
	u64 suspended_time;
	u64 accounting_timestamp;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device___5 *, s32);
	struct dev_pm_qos *qos;
};

struct device_type___5;

struct bus_type___5;

struct device_driver___5;

struct dev_pm_domain___5;

struct fwnode_handle___5;

struct class___5;

struct device___5 {
	struct kobject___5 kobj;
	struct device___5 *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type___5 *type;
	struct bus_type___5 *bus;
	struct device_driver___5 *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info___5 power;
	struct dev_pm_domain___5 *pm_domain;
	struct em_perf_domain *em_pd;
	struct dev_pin_info *pins;
	struct dev_msi_info msi;
	const struct dma_map_ops *dma_ops;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct cma *cma_area;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle___5 *fwnode;
	int numa_node;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	struct class___5 *class;
	const struct attribute_group___5 **groups;
	void (*release)(struct device___5 *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
};

struct net_device___5 {
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
	long unsigned int state;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct list_head ptype_specific;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	unsigned int flags;
	long long unsigned int priv_flags;
	const struct net_device_ops *netdev_ops;
	int ifindex;
	short unsigned int gflags;
	short unsigned int hard_header_len;
	unsigned int mtu;
	short unsigned int needed_headroom;
	short unsigned int needed_tailroom;
	netdev_features_t features;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	netdev_features_t gso_partial_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct iw_handler_def *wireless_handlers;
	struct iw_public_data *wireless_data;
	const struct ethtool_ops *ethtool_ops;
	const struct l3mdev_ops *l3mdev_ops;
	const struct ndisc_ops *ndisc_ops;
	const struct xfrmdev_ops *xfrmdev_ops;
	const struct tlsdev_ops *tlsdev_ops;
	const struct header_ops *header_ops;
	unsigned char operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	short unsigned int padded;
	spinlock_t addr_list_lock;
	int irq;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset___5 *queues_kset;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct inet6_dev *ip6_ptr;
	struct vlan_info *vlan_info;
	struct dsa_port *dsa_ptr;
	struct tipc_bearer *tipc_ptr;
	void *atalk_ptr;
	void *ax25_ptr;
	struct wireless_dev *ieee80211_ptr;
	struct wpan_dev *ieee802154_ptr;
	struct mpls_dev *mpls_ptr;
	struct mctp_dev *mctp_ptr;
	const unsigned char *dev_addr;
	struct netdev_rx_queue *_rx;
	unsigned int num_rx_queues;
	unsigned int real_num_rx_queues;
	struct bpf_prog *xdp_prog;
	long unsigned int gro_flush_timeout;
	int napi_defer_hard_irqs;
	unsigned int gro_max_size;
	rx_handler_func_t___5 *rx_handler;
	void *rx_handler_data;
	struct mini_Qdisc *miniq_ingress;
	struct netdev_queue *ingress_queue;
	struct nf_hook_entries___2 *nf_hooks_ingress;
	unsigned char broadcast[32];
	struct cpu_rmap *rx_cpu_rmap;
	struct hlist_node index_hlist;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netdev_queue *_tx;
	unsigned int num_tx_queues;
	unsigned int real_num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct xps_dev_maps *xps_maps[2];
	struct mini_Qdisc *miniq_egress;
	struct nf_hook_entries___2 *nf_hooks_egress;
	struct hlist_head qdisc_hash[16];
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	int *pcpu_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	enum {
		NETREG_UNINITIALIZED___5 = 0,
		NETREG_REGISTERED___5 = 1,
		NETREG_UNREGISTERING___5 = 2,
		NETREG_UNREGISTERED___5 = 3,
		NETREG_RELEASED___5 = 4,
		NETREG_DUMMY___5 = 5,
	} reg_state: 8;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED___5 = 0,
		RTNL_LINK_INITIALIZING___5 = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device___5 *);
	struct netpoll_info *npinfo;
	possible_net_t nd_net;
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	struct garp_port *garp_port;
	struct mrp_port *mrp_port;
	struct dm_hw_stat_delta *dm_private;
	struct device___5 dev;
	const struct attribute_group___5 *sysfs_groups[4];
	const struct attribute_group___5 *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	unsigned int gso_max_size;
	unsigned int tso_max_size;
	u16 gso_max_segs;
	u16 tso_max_segs;
	const struct dcbnl_rtnl_ops *dcbnl_ops;
	s16 num_tc;
	struct netdev_tc_txq tc_to_txq[16];
	u8 prio_tc_map[16];
	unsigned int fcoe_ddp_xid;
	struct netprio_map *priomap;
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	unsigned int wol_enabled: 1;
	unsigned int threaded: 1;
	struct list_head net_notifier_list;
	const struct macsec_ops *macsec_ops;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	long: 64;
	long: 64;
	long: 64;
};

struct neighbour___3 {
	struct neighbour___3 *next;
	struct neigh_table *tbl;
	struct neigh_parms *parms;
	long unsigned int confirmed;
	long unsigned int updated;
	rwlock_t lock;
	refcount_t refcnt;
	unsigned int arp_queue_len_bytes;
	struct sk_buff_head___5 arp_queue;
	struct timer_list timer;
	long unsigned int used;
	atomic_t probes;
	u8 nud_state;
	u8 type;
	u8 dead;
	u8 protocol;
	u32 flags;
	seqlock_t ha_lock;
	int: 32;
	unsigned char ha[32];
	struct hh_cache hh;
	int (*output)(struct neighbour___3 *, struct sk_buff___5 *);
	const struct neigh_ops *ops;
	struct list_head gc_list;
	struct list_head managed_list;
	struct callback_head rcu;
	struct net_device___5 *dev;
	netdevice_tracker dev_tracker;
	u8 primary_key[0];
};

struct fib6_info___3 {
	struct fib6_table___3 *fib6_table;
	struct fib6_info___3 *fib6_next;
	struct fib6_node *fib6_node;
	union {
		struct list_head fib6_siblings;
		struct list_head nh_list;
	};
	unsigned int fib6_nsiblings;
	refcount_t fib6_ref;
	long unsigned int expires;
	struct dst_metrics *fib6_metrics;
	struct rt6key fib6_dst;
	u32 fib6_flags;
	struct rt6key fib6_src;
	struct rt6key fib6_prefsrc;
	u32 fib6_metric;
	u8 fib6_protocol;
	u8 fib6_type;
	u8 offload;
	u8 trap;
	u8 offload_failed;
	u8 should_flush: 1;
	u8 dst_nocount: 1;
	u8 dst_nopolicy: 1;
	u8 fib6_destroying: 1;
	u8 unused: 4;
	struct callback_head rcu;
	struct nexthop *nh;
	struct fib6_nh fib6_nh[0];
};

struct rt6_info___3 {
	struct dst_entry___3 dst;
	struct fib6_info___3 *from;
	int sernum;
	struct rt6key rt6i_dst;
	struct rt6key rt6i_src;
	struct in6_addr rt6i_gateway;
	struct inet6_dev *rt6i_idev;
	u32 rt6i_flags;
	struct list_head rt6i_uncached;
	struct uncached_list *rt6i_uncached_list;
	short unsigned int rt6i_nfheader_len;
};

struct fib6_table___3 {
	struct hlist_node tb6_hlist;
	u32 tb6_id;
	spinlock_t tb6_lock;
	struct fib6_node tb6_root;
	struct inet_peer_base tb6_peers;
	unsigned int flags;
	unsigned int fib_seq;
};

struct nf_hook_entries___2 {
	u16 num_hook_entries;
	struct nf_hook_entry hooks[0];
};

struct dentry_operations___5;

struct dentry___5 {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry___5 *d_parent;
	struct qstr d_name;
	struct inode___5 *d_inode;
	unsigned char d_iname[32];
	struct lockref d_lockref;
	const struct dentry_operations___5 *d_op;
	struct super_block___5 *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct list_head d_child;
	struct list_head d_subdirs;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

struct inode_operations___5;

struct inode___5 {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations___5 *i_op;
	struct super_block___5 *i_sb;
	struct address_space___5 *i_mapping;
	void *i_security;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback___5 *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations___5 *i_fop;
		void (*free_inode)(struct inode___5 *);
	};
	struct file_lock_context *i_flctx;
	struct address_space___5 i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info___5 *i_pipe;
		struct cdev___2 *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_info *i_crypt_info;
	struct fsverity_info *i_verity_info;
	void *i_private;
};

struct dentry_operations___5 {
	int (*d_revalidate)(struct dentry___5 *, unsigned int);
	int (*d_weak_revalidate)(struct dentry___5 *, unsigned int);
	int (*d_hash)(const struct dentry___5 *, struct qstr *);
	int (*d_compare)(const struct dentry___5 *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry___5 *);
	int (*d_init)(struct dentry___5 *);
	void (*d_release)(struct dentry___5 *);
	void (*d_prune)(struct dentry___5 *);
	void (*d_iput)(struct dentry___5 *, struct inode___5 *);
	char * (*d_dname)(struct dentry___5 *, char *, int);
	struct vfsmount___5 * (*d_automount)(struct path___5 *);
	int (*d_manage)(const struct path___5 *, bool);
	struct dentry___5 * (*d_real)(struct dentry___5 *, const struct inode___5 *);
	long: 64;
	long: 64;
	long: 64;
};

struct quota_format_type___5;

struct mem_dqinfo___5 {
	struct quota_format_type___5 *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};

struct quota_format_ops___5;

struct quota_info___5 {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode___5 *files[3];
	struct mem_dqinfo___5 info[3];
	const struct quota_format_ops___5 *ops[3];
};

struct rcuwait___5 {
	struct task_struct___5 *task;
};

struct percpu_rw_semaphore___5 {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait___5 writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers___5 {
	int frozen;
	wait_queue_head_t wait_unfrozen;
	struct percpu_rw_semaphore___5 rw_sem[3];
};

struct shrink_control___5;

struct shrinker___5 {
	long unsigned int (*count_objects)(struct shrinker___5 *, struct shrink_control___5 *);
	long unsigned int (*scan_objects)(struct shrinker___5 *, struct shrink_control___5 *);
	long int batch;
	int seeks;
	unsigned int flags;
	struct list_head list;
	int id;
	atomic_long_t *nr_deferred;
};

struct super_operations___5;

struct dquot_operations___5;

struct quotactl_ops___5;

struct block_device___5;

struct super_block___5 {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type___5 *s_type;
	const struct super_operations___5 *s_op;
	const struct dquot_operations___5 *dq_op;
	const struct quotactl_ops___5 *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry___5 *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	void *s_security;
	const struct xattr_handler **s_xattr;
	const struct fscrypt_operations *s_cop;
	struct fscrypt_keyring *s_master_keys;
	const struct fsverity_operations *s_vop;
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device___5 *s_bdev;
	struct backing_dev_info___5 *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info___5 s_dquot;
	struct sb_writers___5 s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	__u32 s_fsnotify_mask;
	struct fsnotify_mark_connector *s_fsnotify_marks;
	char s_id[32];
	uuid_t s_uuid;
	unsigned int s_max_links;
	fmode_t s_mode;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations___5 *s_d_op;
	struct shrinker___5 s_shrink;
	atomic_long_t s_remove_count;
	atomic_long_t s_fsnotify_connectors;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 64;
	long: 64;
};

struct vfsmount___5 {
	struct dentry___5 *mnt_root;
	struct super_block___5 *mnt_sb;
	int mnt_flags;
	struct user_namespace *mnt_userns;
};

struct shrink_control___5 {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup___5 *memcg;
};

struct cgroup___5 {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	struct kernfs_node___5 *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	struct cgroup_file psi_files[4];
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[13];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[13];
	struct cgroup___5 *dom_cgrp;
	struct cgroup___5 *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group *psi;
	struct cgroup_bpf bpf;
	atomic_t congestion_count;
	struct cgroup_freezer_state freezer;
	struct cgroup___5 *ancestors[0];
};

struct core_thread___5 {
	struct task_struct___5 *task;
	struct core_thread___5 *next;
};

struct core_state___5 {
	atomic_t nr_threads;
	struct core_thread___5 dumper;
	struct completion startup;
};

struct iattr___5 {
	unsigned int ia_valid;
	umode_t ia_mode;
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file___5 *ia_file;
};

struct dquot___5 {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block___5 *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};

struct quota_format_type___5 {
	int qf_fmt_id;
	const struct quota_format_ops___5 *qf_ops;
	struct module___5 *qf_owner;
	struct quota_format_type___5 *qf_next;
};

struct quota_format_ops___5 {
	int (*check_quota_file)(struct super_block___5 *, int);
	int (*read_file_info)(struct super_block___5 *, int);
	int (*write_file_info)(struct super_block___5 *, int);
	int (*free_file_info)(struct super_block___5 *, int);
	int (*read_dqblk)(struct dquot___5 *);
	int (*commit_dqblk)(struct dquot___5 *);
	int (*release_dqblk)(struct dquot___5 *);
	int (*get_next_id)(struct super_block___5 *, struct kqid *);
};

struct dquot_operations___5 {
	int (*write_dquot)(struct dquot___5 *);
	struct dquot___5 * (*alloc_dquot)(struct super_block___5 *, int);
	void (*destroy_dquot)(struct dquot___5 *);
	int (*acquire_dquot)(struct dquot___5 *);
	int (*release_dquot)(struct dquot___5 *);
	int (*mark_dirty)(struct dquot___5 *);
	int (*write_info)(struct super_block___5 *, int);
	qsize_t * (*get_reserved_space)(struct inode___5 *);
	int (*get_projid)(struct inode___5 *, kprojid_t *);
	int (*get_inode_usage)(struct inode___5 *, qsize_t *);
	int (*get_next_id)(struct super_block___5 *, struct kqid *);
};

struct quotactl_ops___5 {
	int (*quota_on)(struct super_block___5 *, int, int, const struct path___5 *);
	int (*quota_off)(struct super_block___5 *, int);
	int (*quota_enable)(struct super_block___5 *, unsigned int);
	int (*quota_disable)(struct super_block___5 *, unsigned int);
	int (*quota_sync)(struct super_block___5 *, int);
	int (*set_info)(struct super_block___5 *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block___5 *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block___5 *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block___5 *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block___5 *, struct qc_state *);
	int (*rm_xquota)(struct super_block___5 *, unsigned int);
};

struct writeback_control___5;

struct address_space_operations___5 {
	int (*writepage)(struct page___5 *, struct writeback_control___5 *);
	int (*read_folio)(struct file___5 *, struct folio___5 *);
	int (*writepages)(struct address_space___5 *, struct writeback_control___5 *);
	bool (*dirty_folio)(struct address_space___5 *, struct folio___5 *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file___5 *, struct address_space___5 *, loff_t, unsigned int, struct page___5 **, void **);
	int (*write_end)(struct file___5 *, struct address_space___5 *, loff_t, unsigned int, unsigned int, struct page___5 *, void *);
	sector_t (*bmap)(struct address_space___5 *, sector_t);
	void (*invalidate_folio)(struct folio___5 *, size_t, size_t);
	bool (*release_folio)(struct folio___5 *, gfp_t);
	void (*free_folio)(struct folio___5 *);
	ssize_t (*direct_IO)(struct kiocb___5 *, struct iov_iter___5 *);
	int (*migrate_folio)(struct address_space___5 *, struct folio___5 *, struct folio___5 *, enum migrate_mode);
	int (*launder_folio)(struct folio___5 *);
	bool (*is_partially_uptodate)(struct folio___5 *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio___5 *, bool *, bool *);
	int (*error_remove_page)(struct address_space___5 *, struct page___5 *);
	int (*swap_activate)(struct swap_info_struct *, struct file___5 *, sector_t *);
	void (*swap_deactivate)(struct file___5 *);
	int (*swap_rw)(struct kiocb___5 *, struct iov_iter___5 *);
};

struct writeback_control___5 {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_fscache_wb: 1;
	unsigned int no_cgroup_owner: 1;
	unsigned int punt_to_cgroup: 1;
	struct swap_iocb **swap_plug;
	struct bdi_writeback___5 *wb;
	struct inode___5 *inode;
	int wb_id;
	int wb_lcand_id;
	int wb_tcand_id;
	size_t wb_bytes;
	size_t wb_lcand_bytes;
	size_t wb_tcand_bytes;
};

struct inode_operations___5 {
	struct dentry___5 * (*lookup)(struct inode___5 *, struct dentry___5 *, unsigned int);
	const char * (*get_link)(struct dentry___5 *, struct inode___5 *, struct delayed_call *);
	int (*permission)(struct user_namespace *, struct inode___5 *, int);
	struct posix_acl * (*get_acl)(struct inode___5 *, int, bool);
	int (*readlink)(struct dentry___5 *, char *, int);
	int (*create)(struct user_namespace *, struct inode___5 *, struct dentry___5 *, umode_t, bool);
	int (*link)(struct dentry___5 *, struct inode___5 *, struct dentry___5 *);
	int (*unlink)(struct inode___5 *, struct dentry___5 *);
	int (*symlink)(struct user_namespace *, struct inode___5 *, struct dentry___5 *, const char *);
	int (*mkdir)(struct user_namespace *, struct inode___5 *, struct dentry___5 *, umode_t);
	int (*rmdir)(struct inode___5 *, struct dentry___5 *);
	int (*mknod)(struct user_namespace *, struct inode___5 *, struct dentry___5 *, umode_t, dev_t);
	int (*rename)(struct user_namespace *, struct inode___5 *, struct dentry___5 *, struct inode___5 *, struct dentry___5 *, unsigned int);
	int (*setattr)(struct user_namespace *, struct dentry___5 *, struct iattr___5 *);
	int (*getattr)(struct user_namespace *, const struct path___5 *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry___5 *, char *, size_t);
	int (*fiemap)(struct inode___5 *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode___5 *, struct timespec64 *, int);
	int (*atomic_open)(struct inode___5 *, struct dentry___5 *, struct file___5 *, unsigned int, umode_t);
	int (*tmpfile)(struct user_namespace *, struct inode___5 *, struct file___5 *, umode_t);
	int (*set_acl)(struct user_namespace *, struct inode___5 *, struct posix_acl *, int);
	int (*fileattr_set)(struct user_namespace *, struct dentry___5 *, struct fileattr *);
	int (*fileattr_get)(struct dentry___5 *, struct fileattr *);
	long: 64;
};

struct file_lock_operations___5 {
	void (*fl_copy_lock)(struct file_lock___5 *, struct file_lock___5 *);
	void (*fl_release_private)(struct file_lock___5 *);
};

struct lock_manager_operations___5;

struct file_lock___5 {
	struct file_lock___5 *fl_blocker;
	struct list_head fl_list;
	struct hlist_node fl_link;
	struct list_head fl_blocked_requests;
	struct list_head fl_blocked_member;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	unsigned int fl_pid;
	int fl_link_cpu;
	wait_queue_head_t fl_wait;
	struct file___5 *fl_file;
	loff_t fl_start;
	loff_t fl_end;
	struct fasync_struct___5 *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct file_lock_operations___5 *fl_ops;
	const struct lock_manager_operations___5 *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
	} fl_u;
};

struct lock_manager_operations___5 {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock___5 *);
	int (*lm_grant)(struct file_lock___5 *, int);
	bool (*lm_break)(struct file_lock___5 *);
	int (*lm_change)(struct file_lock___5 *, int, struct list_head *);
	void (*lm_setup)(struct file_lock___5 *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lock___5 *);
	bool (*lm_lock_expirable)(struct file_lock___5 *);
	void (*lm_expire_lock)();
};

struct fasync_struct___5 {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct___5 *fa_next;
	struct file___5 *fa_file;
	struct callback_head fa_rcu;
};

struct super_operations___5 {
	struct inode___5 * (*alloc_inode)(struct super_block___5 *);
	void (*destroy_inode)(struct inode___5 *);
	void (*free_inode)(struct inode___5 *);
	void (*dirty_inode)(struct inode___5 *, int);
	int (*write_inode)(struct inode___5 *, struct writeback_control___5 *);
	int (*drop_inode)(struct inode___5 *);
	void (*evict_inode)(struct inode___5 *);
	void (*put_super)(struct super_block___5 *);
	int (*sync_fs)(struct super_block___5 *, int);
	int (*freeze_super)(struct super_block___5 *);
	int (*freeze_fs)(struct super_block___5 *);
	int (*thaw_super)(struct super_block___5 *);
	int (*unfreeze_fs)(struct super_block___5 *);
	int (*statfs)(struct dentry___5 *, struct kstatfs *);
	int (*remount_fs)(struct super_block___5 *, int *, char *);
	void (*umount_begin)(struct super_block___5 *);
	int (*show_options)(struct seq_file___5 *, struct dentry___5 *);
	int (*show_devname)(struct seq_file___5 *, struct dentry___5 *);
	int (*show_path)(struct seq_file___5 *, struct dentry___5 *);
	int (*show_stats)(struct seq_file___5 *, struct dentry___5 *);
	ssize_t (*quota_read)(struct super_block___5 *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block___5 *, int, const char *, size_t, loff_t);
	struct dquot___5 ** (*get_dquots)(struct inode___5 *);
	long int (*nr_cached_objects)(struct super_block___5 *, struct shrink_control___5 *);
	long int (*free_cached_objects)(struct super_block___5 *, struct shrink_control___5 *);
};

struct block_device___5 {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	bool bd_read_only;
	dev_t bd_dev;
	atomic_t bd_openers;
	struct inode___5 *bd_inode;
	struct super_block___5 *bd_super;
	void *bd_claiming;
	struct device___5 bd_device;
	void *bd_holder;
	int bd_holders;
	bool bd_write_holder;
	struct kobject___5 *bd_holder_dir;
	u8 bd_partno;
	spinlock_t bd_size_lock;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	int bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct super_block___5 *bd_fsfreeze_sb;
	struct partition_meta_info *bd_meta_info;
};

typedef void (*poll_queue_proc___5)(struct file___5 *, wait_queue_head_t *, struct poll_table_struct___5 *);

struct poll_table_struct___5 {
	poll_queue_proc___5 _qproc;
	__poll_t _key;
};

struct seq_file___5 {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations___5 *op;
	int poll_event;
	const struct file___5 *file;
	void *private;
};

typedef void bio_end_io_t___5(struct bio___5 *);

struct bio___5 {
	struct bio___5 *bi_next;
	struct block_device___5 *bi_bdev;
	blk_opf_t bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t___5 *bi_end_io;
	void *bi_private;
	struct blkcg_gq *bi_blkg;
	struct bio_issue bi_issue;
	u64 bi_iocost_cost;
	struct bio_crypt_ctx *bi_crypt_context;
	union {
		struct bio_integrity_payload *bi_integrity;
	};
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec___5 *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec___5 bi_inline_vecs[0];
};

struct dev_pagemap_ops___5 {
	void (*page_free)(struct page___5 *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault___5 *);
	int (*memory_failure)(struct dev_pagemap___5 *, long unsigned int, long unsigned int, int);
};

struct socket_wq___5 {
	wait_queue_head_t wait;
	struct fasync_struct___5 *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
	long: 64;
};

struct proto_ops___5;

struct socket___5 {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file___5 *file;
	struct sock___5 *sk;
	const struct proto_ops___5 *ops;
	long: 64;
	long: 64;
	long: 64;
	struct socket_wq___5 wq;
};

typedef int (*sk_read_actor_t___5)(read_descriptor_t *, struct sk_buff___5 *, unsigned int, size_t);

typedef int (*skb_read_actor_t___5)(struct sock___5 *, struct sk_buff___5 *);

struct proto_ops___5 {
	int family;
	struct module___5 *owner;
	int (*release)(struct socket___5 *);
	int (*bind)(struct socket___5 *, struct sockaddr *, int);
	int (*connect)(struct socket___5 *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket___5 *, struct socket___5 *);
	int (*accept)(struct socket___5 *, struct socket___5 *, int, bool);
	int (*getname)(struct socket___5 *, struct sockaddr *, int);
	__poll_t (*poll)(struct file___5 *, struct socket___5 *, struct poll_table_struct___5 *);
	int (*ioctl)(struct socket___5 *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct socket___5 *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket___5 *, void *, bool, bool);
	int (*listen)(struct socket___5 *, int);
	int (*shutdown)(struct socket___5 *, int);
	int (*setsockopt)(struct socket___5 *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket___5 *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file___5 *, struct socket___5 *);
	int (*sendmsg)(struct socket___5 *, struct msghdr___5 *, size_t);
	int (*recvmsg)(struct socket___5 *, struct msghdr___5 *, size_t, int);
	int (*mmap)(struct file___5 *, struct socket___5 *, struct vm_area_struct___5 *);
	ssize_t (*sendpage)(struct socket___5 *, struct page___5 *, int, size_t, int);
	ssize_t (*splice_read)(struct socket___5 *, loff_t *, struct pipe_inode_info___5 *, size_t, unsigned int);
	int (*set_peek_off)(struct sock___5 *, int);
	int (*peek_len)(struct socket___5 *);
	int (*read_sock)(struct sock___5 *, read_descriptor_t *, sk_read_actor_t___5);
	int (*read_skb)(struct sock___5 *, skb_read_actor_t___5);
	int (*sendpage_locked)(struct sock___5 *, struct page___5 *, int, size_t, int);
	int (*sendmsg_locked)(struct sock___5 *, struct msghdr___5 *, size_t);
	int (*set_rcvlowat)(struct sock___5 *, int);
};

struct kernfs_elem_symlink___5 {
	struct kernfs_node___5 *target_kn;
};

struct kernfs_ops___5;

struct kernfs_elem_attr___5 {
	const struct kernfs_ops___5 *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node___5 *notify_next;
};

struct kernfs_node___5 {
	atomic_t count;
	atomic_t active;
	struct kernfs_node___5 *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink___5 symlink;
		struct kernfs_elem_attr___5 attr;
	};
	void *priv;
	u64 id;
	short unsigned int flags;
	umode_t mode;
	struct kernfs_iattrs *iattr;
};

struct kernfs_open_file___5;

struct kernfs_ops___5 {
	int (*open)(struct kernfs_open_file___5 *);
	void (*release)(struct kernfs_open_file___5 *);
	int (*seq_show)(struct seq_file___5 *, void *);
	void * (*seq_start)(struct seq_file___5 *, loff_t *);
	void * (*seq_next)(struct seq_file___5 *, void *, loff_t *);
	void (*seq_stop)(struct seq_file___5 *, void *);
	ssize_t (*read)(struct kernfs_open_file___5 *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file___5 *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file___5 *, struct poll_table_struct___5 *);
	int (*mmap)(struct kernfs_open_file___5 *, struct vm_area_struct___5 *);
};

struct kernfs_open_file___5 {
	struct kernfs_node___5 *kn;
	struct file___5 *file;
	struct seq_file___5 *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct___5 *vm_ops;
};

struct kobj_ns_type_operations___5 {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock___5 *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

struct bin_attribute___5 {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space___5 * (*f_mapping)();
	ssize_t (*read)(struct file___5 *, struct kobject___5 *, struct bin_attribute___5 *, char *, loff_t, size_t);
	ssize_t (*write)(struct file___5 *, struct kobject___5 *, struct bin_attribute___5 *, char *, loff_t, size_t);
	int (*mmap)(struct file___5 *, struct kobject___5 *, struct bin_attribute___5 *, struct vm_area_struct___5 *);
};

struct sysfs_ops___5 {
	ssize_t (*show)(struct kobject___5 *, struct attribute *, char *);
	ssize_t (*store)(struct kobject___5 *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops___5;

struct kset___5 {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject___5 kobj;
	const struct kset_uevent_ops___5 *uevent_ops;
};

struct kobj_type___5 {
	void (*release)(struct kobject___5 *);
	const struct sysfs_ops___5 *sysfs_ops;
	const struct attribute_group___5 **default_groups;
	const struct kobj_ns_type_operations___5 * (*child_ns_type)(struct kobject___5 *);
	const void * (*namespace)(struct kobject___5 *);
	void (*get_ownership)(struct kobject___5 *, kuid_t *, kgid_t *);
};

struct kset_uevent_ops___5 {
	int (* const filter)(struct kobject___5 *);
	const char * (* const name)(struct kobject___5 *);
	int (* const uevent)(struct kobject___5 *, struct kobj_uevent_env *);
};

struct dev_pm_ops___5 {
	int (*prepare)(struct device___5 *);
	void (*complete)(struct device___5 *);
	int (*suspend)(struct device___5 *);
	int (*resume)(struct device___5 *);
	int (*freeze)(struct device___5 *);
	int (*thaw)(struct device___5 *);
	int (*poweroff)(struct device___5 *);
	int (*restore)(struct device___5 *);
	int (*suspend_late)(struct device___5 *);
	int (*resume_early)(struct device___5 *);
	int (*freeze_late)(struct device___5 *);
	int (*thaw_early)(struct device___5 *);
	int (*poweroff_late)(struct device___5 *);
	int (*restore_early)(struct device___5 *);
	int (*suspend_noirq)(struct device___5 *);
	int (*resume_noirq)(struct device___5 *);
	int (*freeze_noirq)(struct device___5 *);
	int (*thaw_noirq)(struct device___5 *);
	int (*poweroff_noirq)(struct device___5 *);
	int (*restore_noirq)(struct device___5 *);
	int (*runtime_suspend)(struct device___5 *);
	int (*runtime_resume)(struct device___5 *);
	int (*runtime_idle)(struct device___5 *);
};

struct wakeup_source___5 {
	const char *name;
	int id;
	struct list_head entry;
	spinlock_t lock;
	struct wake_irq *wakeirq;
	struct timer_list timer;
	long unsigned int timer_expires;
	ktime_t total_time;
	ktime_t max_time;
	ktime_t last_time;
	ktime_t start_prevent_time;
	ktime_t prevent_sleep_time;
	long unsigned int event_count;
	long unsigned int active_count;
	long unsigned int relax_count;
	long unsigned int expire_count;
	long unsigned int wakeup_count;
	struct device___5 *dev;
	bool active: 1;
	bool autosleep_enabled: 1;
};

struct dev_pm_domain___5 {
	struct dev_pm_ops___5 ops;
	int (*start)(struct device___5 *);
	void (*detach)(struct device___5 *, bool);
	int (*activate)(struct device___5 *);
	void (*sync)(struct device___5 *);
	void (*dismiss)(struct device___5 *);
};

struct bus_type___5 {
	const char *name;
	const char *dev_name;
	struct device___5 *dev_root;
	const struct attribute_group___5 **bus_groups;
	const struct attribute_group___5 **dev_groups;
	const struct attribute_group___5 **drv_groups;
	int (*match)(struct device___5 *, struct device_driver___5 *);
	int (*uevent)(struct device___5 *, struct kobj_uevent_env *);
	int (*probe)(struct device___5 *);
	void (*sync_state)(struct device___5 *);
	void (*remove)(struct device___5 *);
	void (*shutdown)(struct device___5 *);
	int (*online)(struct device___5 *);
	int (*offline)(struct device___5 *);
	int (*suspend)(struct device___5 *, pm_message_t);
	int (*resume)(struct device___5 *);
	int (*num_vf)(struct device___5 *);
	int (*dma_configure)(struct device___5 *);
	void (*dma_cleanup)(struct device___5 *);
	const struct dev_pm_ops___5 *pm;
	const struct iommu_ops *iommu_ops;
	struct subsys_private *p;
	struct lock_class_key lock_key;
	bool need_parent_lock;
};

struct device_driver___5 {
	const char *name;
	struct bus_type___5 *bus;
	struct module___5 *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device___5 *);
	void (*sync_state)(struct device___5 *);
	int (*remove)(struct device___5 *);
	void (*shutdown)(struct device___5 *);
	int (*suspend)(struct device___5 *, pm_message_t);
	int (*resume)(struct device___5 *);
	const struct attribute_group___5 **groups;
	const struct attribute_group___5 **dev_groups;
	const struct dev_pm_ops___5 *pm;
	void (*coredump)(struct device___5 *);
	struct driver_private *p;
};

struct device_type___5 {
	const char *name;
	const struct attribute_group___5 **groups;
	int (*uevent)(struct device___5 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___5 *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device___5 *);
	const struct dev_pm_ops___5 *pm;
};

struct class___5 {
	const char *name;
	struct module___5 *owner;
	const struct attribute_group___5 **class_groups;
	const struct attribute_group___5 **dev_groups;
	struct kobject___5 *dev_kobj;
	int (*dev_uevent)(struct device___5 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___5 *, umode_t *);
	void (*class_release)(struct class___5 *);
	void (*dev_release)(struct device___5 *);
	int (*shutdown_pre)(struct device___5 *);
	const struct kobj_ns_type_operations___5 *ns_type;
	const void * (*namespace)(struct device___5 *);
	void (*get_ownership)(struct device___5 *, kuid_t *, kgid_t *);
	const struct dev_pm_ops___5 *pm;
	struct subsys_private *p;
};

struct kparam_array___5;

struct kernel_param___5 {
	const char *name;
	struct module___5 *mod;
	const struct kernel_param_ops___5 *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array___5 *arr;
	};
};

struct kparam_array___5 {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops___5 *ops;
	void *elem;
};

struct module_attribute___5 {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute___5 *, struct module_kobject___5 *, char *);
	ssize_t (*store)(struct module_attribute___5 *, struct module_kobject___5 *, const char *, size_t);
	void (*setup)(struct module___5 *, const char *);
	int (*test)(struct module___5 *);
	void (*free)(struct module___5 *);
};

struct fwnode_operations___5;

struct fwnode_handle___5 {
	struct fwnode_handle___5 *secondary;
	const struct fwnode_operations___5 *ops;
	struct device___5 *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

struct fwnode_reference_args___5;

struct fwnode_endpoint___5;

struct fwnode_operations___5 {
	struct fwnode_handle___5 * (*get)(struct fwnode_handle___5 *);
	void (*put)(struct fwnode_handle___5 *);
	bool (*device_is_available)(const struct fwnode_handle___5 *);
	const void * (*device_get_match_data)(const struct fwnode_handle___5 *, const struct device___5 *);
	bool (*device_dma_supported)(const struct fwnode_handle___5 *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle___5 *);
	bool (*property_present)(const struct fwnode_handle___5 *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle___5 *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle___5 *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle___5 *);
	const char * (*get_name_prefix)(const struct fwnode_handle___5 *);
	struct fwnode_handle___5 * (*get_parent)(const struct fwnode_handle___5 *);
	struct fwnode_handle___5 * (*get_next_child_node)(const struct fwnode_handle___5 *, struct fwnode_handle___5 *);
	struct fwnode_handle___5 * (*get_named_child_node)(const struct fwnode_handle___5 *, const char *);
	int (*get_reference_args)(const struct fwnode_handle___5 *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args___5 *);
	struct fwnode_handle___5 * (*graph_get_next_endpoint)(const struct fwnode_handle___5 *, struct fwnode_handle___5 *);
	struct fwnode_handle___5 * (*graph_get_remote_endpoint)(const struct fwnode_handle___5 *);
	struct fwnode_handle___5 * (*graph_get_port_parent)(struct fwnode_handle___5 *);
	int (*graph_parse_endpoint)(const struct fwnode_handle___5 *, struct fwnode_endpoint___5 *);
	void * (*iomap)(struct fwnode_handle___5 *, int);
	int (*irq_get)(const struct fwnode_handle___5 *, unsigned int);
	int (*add_links)(struct fwnode_handle___5 *);
};

struct fwnode_endpoint___5 {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle___5 *local_fwnode;
};

struct fwnode_reference_args___5 {
	struct fwnode_handle___5 *fwnode;
	unsigned int nargs;
	u64 args[8];
};

struct pipe_buf_operations___5;

struct pipe_buffer___5 {
	struct page___5 *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations___5 *ops;
	unsigned int flags;
	long unsigned int private;
};

struct pipe_buf_operations___5 {
	int (*confirm)(struct pipe_inode_info___5 *, struct pipe_buffer___5 *);
	void (*release)(struct pipe_inode_info___5 *, struct pipe_buffer___5 *);
	bool (*try_steal)(struct pipe_inode_info___5 *, struct pipe_buffer___5 *);
	bool (*get)(struct pipe_inode_info___5 *, struct pipe_buffer___5 *);
};

typedef struct bio_vec___5 skb_frag_t___4;

struct skb_shared_info___4 {
	__u8 flags;
	__u8 meta_len;
	__u8 nr_frags;
	__u8 tx_flags;
	short unsigned int gso_size;
	short unsigned int gso_segs;
	struct sk_buff___5 *frag_list;
	struct skb_shared_hwtstamps hwtstamps;
	unsigned int gso_type;
	u32 tskey;
	atomic_t dataref;
	unsigned int xdp_frags_size;
	void *destructor_arg;
	skb_frag_t___4 frags[17];
};

typedef unsigned int nf_hookfn___3(void *, struct sk_buff___5 *, const struct nf_hook_state *);

enum ofp12_ipv6exthdr_flags {
	OFPIEH12_NONEXT = 1,
	OFPIEH12_ESP = 2,
	OFPIEH12_AUTH = 4,
	OFPIEH12_DEST = 8,
	OFPIEH12_FRAG = 16,
	OFPIEH12_ROUTER = 32,
	OFPIEH12_HOP = 64,
	OFPIEH12_UNREP = 128,
	OFPIEH12_UNSEQ = 256,
};

struct arp_eth_header {
	__be16 ar_hrd;
	__be16 ar_pro;
	unsigned char ar_hln;
	unsigned char ar_pln;
	__be16 ar_op;
	unsigned char ar_sha[6];
	unsigned char ar_sip[4];
	unsigned char ar_tha[6];
	unsigned char ar_tip[4];
};

struct llc_snap_hdr {
	u8 dsap;
	u8 ssap;
	u8 ctrl;
	u8 oui[3];
	__be16 ethertype;
};

struct kset___6;

struct kobj_type___6;

struct kernfs_node___6;

struct kobject___6 {
	const char *name;
	struct list_head entry;
	struct kobject___6 *parent;
	struct kset___6 *kset;
	const struct kobj_type___6 *ktype;
	struct kernfs_node___6 *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct module___6;

struct module_kobject___6 {
	struct kobject___6 kobj;
	struct module___6 *mod;
	struct kobject___6 *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct mod_tree_node___6 {
	struct module___6 *mod;
	struct latch_tree_node node;
};

struct module_layout___6 {
	void *base;
	unsigned int size;
	unsigned int text_size;
	unsigned int ro_size;
	unsigned int ro_after_init_size;
	struct mod_tree_node___6 mtn;
};

struct module_attribute___6;

struct kernel_param___6;

struct module___6 {
	enum module_state state;
	struct list_head list;
	char name[56];
	struct module_kobject___6 mkobj;
	struct module_attribute___6 *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject___6 *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param___6 *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool sig_ok;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	struct module_layout___6 core_layout;
	struct module_layout___6 init_layout;
	struct mod_arch_specific arch;
	long unsigned int taints;
	unsigned int num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map___3 *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	int num_static_call_sites;
	struct static_call_site *static_call_sites;
	int num_kunit_suites;
	struct kunit_suite **kunit_suites;
	bool klp;
	bool klp_alive;
	struct klp_modinfo *klp_info;
	unsigned int printk_index_size;
	struct pi_entry **printk_index_start;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
};

struct dentry___6;

struct super_block___6;

struct file_system_type___6 {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry___6 * (*mount)(struct file_system_type___6 *, int, const char *, void *);
	void (*kill_sb)(struct super_block___6 *);
	struct module___6 *owner;
	struct file_system_type___6 *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

struct kernel_param_ops___6 {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param___6 *);
	int (*get)(char *, const struct kernel_param___6 *);
	void (*free)(void *);
};

struct file___6;

struct kiocb___6;

struct iov_iter___6;

struct poll_table_struct___6;

struct vm_area_struct___6;

struct inode___6;

struct file_lock___6;

struct page___6;

struct pipe_inode_info___6;

struct seq_file___6;

struct file_operations___6 {
	struct module___6 *owner;
	loff_t (*llseek)(struct file___6 *, loff_t, int);
	ssize_t (*read)(struct file___6 *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file___6 *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb___6 *, struct iov_iter___6 *);
	ssize_t (*write_iter)(struct kiocb___6 *, struct iov_iter___6 *);
	int (*iopoll)(struct kiocb___6 *, struct io_comp_batch *, unsigned int);
	int (*iterate)(struct file___6 *, struct dir_context *);
	int (*iterate_shared)(struct file___6 *, struct dir_context *);
	__poll_t (*poll)(struct file___6 *, struct poll_table_struct___6 *);
	long int (*unlocked_ioctl)(struct file___6 *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file___6 *, unsigned int, long unsigned int);
	int (*mmap)(struct file___6 *, struct vm_area_struct___6 *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode___6 *, struct file___6 *);
	int (*flush)(struct file___6 *, fl_owner_t);
	int (*release)(struct inode___6 *, struct file___6 *);
	int (*fsync)(struct file___6 *, loff_t, loff_t, int);
	int (*fasync)(int, struct file___6 *, int);
	int (*lock)(struct file___6 *, int, struct file_lock___6 *);
	ssize_t (*sendpage)(struct file___6 *, struct page___6 *, int, size_t, loff_t *, int);
	long unsigned int (*get_unmapped_area)(struct file___6 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file___6 *, int, struct file_lock___6 *);
	ssize_t (*splice_write)(struct pipe_inode_info___6 *, struct file___6 *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file___6 *, loff_t *, struct pipe_inode_info___6 *, size_t, unsigned int);
	int (*setlease)(struct file___6 *, long int, struct file_lock___6 **, void **);
	long int (*fallocate)(struct file___6 *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file___6 *, struct file___6 *);
	ssize_t (*copy_file_range)(struct file___6 *, loff_t, struct file___6 *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file___6 *, loff_t, struct file___6 *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file___6 *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

typedef struct page___6 *pgtable_t___6;

struct address_space___6;

struct page_pool___6;

struct mm_struct___6;

struct dev_pagemap___6;

struct page___6 {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space___6 *mapping;
			long unsigned int index;
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool___6 *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			union {
				long unsigned int dma_addr_upper;
				atomic_long_t pp_frag_count;
			};
		};
		struct {
			long unsigned int compound_head;
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			atomic_t compound_pincount;
			unsigned int compound_nr;
		};
		struct {
			long unsigned int _compound_pad_1;
			long unsigned int _compound_pad_2;
			struct list_head deferred_list;
		};
		struct {
			long unsigned int _pt_pad_1;
			pgtable_t___6 pmd_huge_pte;
			long unsigned int _pt_pad_2;
			union {
				struct mm_struct___6 *pt_mm;
				atomic_t pt_frag_refcount;
			};
			spinlock_t ptl;
		};
		struct {
			struct dev_pagemap___6 *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	long unsigned int memcg_data;
};

struct page_frag___6 {
	struct page___6 *page;
	__u32 offset;
	__u32 size;
};

struct nsproxy___6;

struct signal_struct___6;

struct bio_list___6;

struct backing_dev_info___6;

struct css_set___6;

struct mem_cgroup___6;

struct vm_struct___6;

struct task_struct___6 {
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct___6 *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	const struct sched_class *sched_class;
	struct rb_node core_node;
	long unsigned int core_cookie;
	unsigned int core_occupation;
	struct task_group *sched_task_group;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_statistics stats;
	struct hlist_head preempt_notifiers;
	unsigned int btrace_seq;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct___6 *mm;
	struct mm_struct___6 *active_mm;
	struct task_rss_stat rss_stat;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	unsigned int sched_psi_wake_requeue: 1;
	int: 28;
	unsigned int sched_remote_wakeup: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int in_user_fault: 1;
	unsigned int in_lru_fault: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_page_owner: 1;
	unsigned int in_eventfd: 1;
	unsigned int pasid_activated: 1;
	unsigned int reported_split_lock: 1;
	unsigned int in_thrashing: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct___6 *real_parent;
	struct task_struct___6 *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct___6 *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid___2 *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_group;
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	struct vtime vtime;
	atomic_t tick_dep_mask;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	struct posix_cputimers_work posix_cputimers_work;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy___6 *nsproxy;
	struct signal_struct___6 *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct audit_context *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct___6 *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	void *journal_info;
	struct bio_list___6 *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct backing_dev_info___6 *backing_dev_info;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	unsigned int psi_flags;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
	struct css_set___6 *cgroups;
	struct list_head cg_list;
	u32 closid;
	u32 rmid;
	struct robust_list_head *robust_list;
	struct compat_robust_list_head *compat_robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	struct perf_event_context *perf_event_ctxp[2];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	long unsigned int preempt_disable_ip;
	struct mempolicy *mempolicy;
	short int il_prev;
	short int pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	long unsigned int numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct numa_group *numa_group;
	long unsigned int *numa_faults;
	long unsigned int total_numa_faults;
	long unsigned int numa_faults_locality[3];
	long unsigned int numa_pages_migrated;
	struct rseq *rseq;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	struct tlbflush_unmap_batch tlb_ubc;
	union {
		refcount_t rcu_users;
		struct callback_head rcu;
	};
	struct pipe_inode_info___6 *splice_pipe;
	struct page_frag___6 task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	int latency_record_count;
	struct latency_record latency_record[32];
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	struct kunit *kunit_test;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace_recursion;
	struct mem_cgroup___6 *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup___6 *active_memcg;
	struct request_queue *throttle_queue;
	struct uprobe_task *utask;
	unsigned int sequential_io;
	unsigned int sequential_io_avg;
	struct kmap_ctrl kmap_ctrl;
	int pagefault_disabled;
	struct task_struct___6 *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct___6 *stack_vm_area;
	refcount_t stack_refcount;
	int patch_state;
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	void *mce_vaddr;
	__u64 mce_kflags;
	u64 mce_addr;
	__u64 mce_ripv: 1;
	__u64 mce_whole_page: 1;
	__u64 __mce_reserved: 62;
	struct callback_head mce_kill_me;
	int mce_count;
	struct llist_head kretprobe_instances;
	struct llist_head rethooks;
	struct callback_head l1d_flush_kill;
	union rv_task_monitor rv[1];
	struct thread_struct thread;
};

struct mm_struct___6 {
	struct {
		struct maple_tree mm_mt;
		long unsigned int (*get_unmapped_area)(struct file___6 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int mmap_compat_base;
		long unsigned int mmap_compat_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		atomic_t mm_count;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[48];
		struct mm_rss_stat rss_stat;
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct___6 *owner;
		struct user_namespace *user_ns;
		struct file___6 *exe_file;
		struct mmu_notifier_subscriptions *notifier_subscriptions;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		atomic_t tlb_flush_batched;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		u32 pasid;
		long unsigned int ksm_merging_pages;
		long unsigned int ksm_rmap_items;
		struct {
			struct list_head list;
			long unsigned int bitmap;
			struct mem_cgroup___6 *memcg;
		} lru_gen;
	};
	long unsigned int cpu_bitmap[0];
};

struct vm_operations_struct___6;

struct vm_area_struct___6 {
	long unsigned int vm_start;
	long unsigned int vm_end;
	struct mm_struct___6 *vm_mm;
	pgprot_t vm_page_prot;
	long unsigned int vm_flags;
	union {
		struct {
			struct rb_node rb;
			long unsigned int rb_subtree_last;
		} shared;
		struct anon_vma_name *anon_name;
	};
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct___6 *vm_ops;
	long unsigned int vm_pgoff;
	struct file___6 *vm_file;
	void *vm_private_data;
	atomic_long_t swap_readahead_info;
	struct mempolicy *vm_policy;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

struct bin_attribute___6;

struct attribute_group___6 {
	const char *name;
	umode_t (*is_visible)(struct kobject___6 *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject___6 *, struct bin_attribute___6 *, int);
	struct attribute **attrs;
	struct bin_attribute___6 **bin_attrs;
};

struct seq_operations___6 {
	void * (*start)(struct seq_file___6 *, loff_t *);
	void (*stop)(struct seq_file___6 *, void *);
	void * (*next)(struct seq_file___6 *, void *, loff_t *);
	int (*show)(struct seq_file___6 *, void *);
};

struct dentry_operations___6;

struct dentry___6 {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry___6 *d_parent;
	struct qstr d_name;
	struct inode___6 *d_inode;
	unsigned char d_iname[32];
	struct lockref d_lockref;
	const struct dentry_operations___6 *d_op;
	struct super_block___6 *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct list_head d_child;
	struct list_head d_subdirs;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

struct address_space_operations___6;

struct address_space___6 {
	struct inode___6 *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	struct rw_semaphore i_mmap_rwsem;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations___6 *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t private_lock;
	struct list_head private_list;
	void *private_data;
};

struct inode_operations___6;

struct bdi_writeback___6;

struct inode___6 {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations___6 *i_op;
	struct super_block___6 *i_sb;
	struct address_space___6 *i_mapping;
	void *i_security;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback___6 *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations___6 *i_fop;
		void (*free_inode)(struct inode___6 *);
	};
	struct file_lock_context *i_flctx;
	struct address_space___6 i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info___6 *i_pipe;
		struct cdev___2 *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_info *i_crypt_info;
	struct fsverity_info *i_verity_info;
	void *i_private;
};

struct vfsmount___6;

struct path___6;

struct dentry_operations___6 {
	int (*d_revalidate)(struct dentry___6 *, unsigned int);
	int (*d_weak_revalidate)(struct dentry___6 *, unsigned int);
	int (*d_hash)(const struct dentry___6 *, struct qstr *);
	int (*d_compare)(const struct dentry___6 *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry___6 *);
	int (*d_init)(struct dentry___6 *);
	void (*d_release)(struct dentry___6 *);
	void (*d_prune)(struct dentry___6 *);
	void (*d_iput)(struct dentry___6 *, struct inode___6 *);
	char * (*d_dname)(struct dentry___6 *, char *, int);
	struct vfsmount___6 * (*d_automount)(struct path___6 *);
	int (*d_manage)(const struct path___6 *, bool);
	struct dentry___6 * (*d_real)(struct dentry___6 *, const struct inode___6 *);
	long: 64;
	long: 64;
	long: 64;
};

struct quota_format_type___6;

struct mem_dqinfo___6 {
	struct quota_format_type___6 *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};

struct quota_format_ops___6;

struct quota_info___6 {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode___6 *files[3];
	struct mem_dqinfo___6 info[3];
	const struct quota_format_ops___6 *ops[3];
};

struct rcuwait___6 {
	struct task_struct___6 *task;
};

struct percpu_rw_semaphore___6 {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait___6 writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers___6 {
	int frozen;
	wait_queue_head_t wait_unfrozen;
	struct percpu_rw_semaphore___6 rw_sem[3];
};

struct shrink_control___6;

struct shrinker___6 {
	long unsigned int (*count_objects)(struct shrinker___6 *, struct shrink_control___6 *);
	long unsigned int (*scan_objects)(struct shrinker___6 *, struct shrink_control___6 *);
	long int batch;
	int seeks;
	unsigned int flags;
	struct list_head list;
	int id;
	atomic_long_t *nr_deferred;
};

struct super_operations___6;

struct dquot_operations___6;

struct quotactl_ops___6;

struct block_device___6;

struct super_block___6 {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type___6 *s_type;
	const struct super_operations___6 *s_op;
	const struct dquot_operations___6 *dq_op;
	const struct quotactl_ops___6 *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry___6 *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	void *s_security;
	const struct xattr_handler **s_xattr;
	const struct fscrypt_operations *s_cop;
	struct fscrypt_keyring *s_master_keys;
	const struct fsverity_operations *s_vop;
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device___6 *s_bdev;
	struct backing_dev_info___6 *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info___6 s_dquot;
	struct sb_writers___6 s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	__u32 s_fsnotify_mask;
	struct fsnotify_mark_connector *s_fsnotify_marks;
	char s_id[32];
	uuid_t s_uuid;
	unsigned int s_max_links;
	fmode_t s_mode;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations___6 *s_d_op;
	struct shrinker___6 s_shrink;
	atomic_long_t s_remove_count;
	atomic_long_t s_fsnotify_connectors;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 64;
	long: 64;
};

struct vfsmount___6 {
	struct dentry___6 *mnt_root;
	struct super_block___6 *mnt_sb;
	int mnt_flags;
	struct user_namespace *mnt_userns;
};

struct path___6 {
	struct vfsmount___6 *mnt;
	struct dentry___6 *dentry;
};

struct shrink_control___6 {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup___6 *memcg;
};

struct mem_cgroup___6 {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct page_counter memory;
	union {
		struct page_counter swap;
		struct page_counter memsw;
	};
	struct page_counter kmem;
	struct page_counter tcpmem;
	struct work_struct high_work;
	long unsigned int zswap_max;
	long unsigned int soft_limit;
	struct vmpressure vmpressure;
	bool oom_group;
	bool oom_lock;
	int under_oom;
	int swappiness;
	int oom_kill_disable;
	struct cgroup_file events_file;
	struct cgroup_file events_local_file;
	struct cgroup_file swap_events_file;
	struct mutex thresholds_lock;
	struct mem_cgroup_thresholds thresholds;
	struct mem_cgroup_thresholds memsw_thresholds;
	struct list_head oom_notify;
	long unsigned int move_charge_at_immigrate;
	spinlock_t move_lock;
	long unsigned int move_lock_flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct memcg_vmstats *vmstats;
	atomic_long_t memory_events[9];
	atomic_long_t memory_events_local[9];
	long unsigned int socket_pressure;
	bool tcpmem_active;
	int tcpmem_pressure;
	int kmemcg_id;
	struct obj_cgroup *objcg;
	struct list_head objcg_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	atomic_t moving_account;
	struct task_struct___6 *move_lock_task;
	struct memcg_vmstats_percpu *vmstats_percpu;
	struct list_head cgwb_list;
	struct wb_domain cgwb_domain;
	struct memcg_cgwb_frn cgwb_frn[4];
	struct list_head event_list;
	spinlock_t event_list_lock;
	struct deferred_split deferred_split_queue;
	struct lru_gen_mm_list mm_list;
	struct mem_cgroup_per_node *nodeinfo[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct device___6;

struct page_pool_params___6 {
	unsigned int flags;
	unsigned int order;
	unsigned int pool_size;
	int nid;
	struct device___6 *dev;
	enum dma_data_direction dma_dir;
	unsigned int max_len;
	unsigned int offset;
	void (*init_callback)(struct page___6 *, void *);
	void *init_arg;
};

struct pp_alloc_cache___6 {
	u32 count;
	struct page___6 *cache[128];
};

struct page_pool___6 {
	struct page_pool_params___6 p;
	struct delayed_work release_dw;
	void (*disconnect)(void *);
	long unsigned int defer_start;
	long unsigned int defer_warn;
	u32 pages_state_hold_cnt;
	unsigned int frag_offset;
	struct page___6 *frag_page;
	long int frag_users;
	u32 xdp_mem_id;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct pp_alloc_cache___6 alloc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct ptr_ring ring;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct dev_pagemap_ops___6;

struct dev_pagemap___6 {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops___6 *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct range ranges[0];
	};
};

struct folio___6 {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space___6 *mapping;
			long unsigned int index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page___6 page;
	};
	long unsigned int _flags_1;
	long unsigned int __head;
	unsigned char _folio_dtor;
	unsigned char _folio_order;
	atomic_t _total_mapcount;
	atomic_t _pincount;
	unsigned int _folio_nr_pages;
};

struct file___6 {
	union {
		struct llist_node f_llist;
		struct callback_head f_rcuhead;
		unsigned int f_iocb_flags;
	};
	struct path___6 f_path;
	struct inode___6 *f_inode;
	const struct file_operations___6 *f_op;
	spinlock_t f_lock;
	atomic_long_t f_count;
	unsigned int f_flags;
	fmode_t f_mode;
	struct mutex f_pos_lock;
	loff_t f_pos;
	struct fown_struct___2 f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	u64 f_version;
	void *f_security;
	void *private_data;
	struct hlist_head *f_ep;
	struct address_space___6 *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};

struct vm_fault___6;

struct vm_operations_struct___6 {
	void (*open)(struct vm_area_struct___6 *);
	void (*close)(struct vm_area_struct___6 *);
	int (*may_split)(struct vm_area_struct___6 *, long unsigned int);
	int (*mremap)(struct vm_area_struct___6 *);
	int (*mprotect)(struct vm_area_struct___6 *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault___6 *);
	vm_fault_t (*huge_fault)(struct vm_fault___6 *, enum page_entry_size);
	vm_fault_t (*map_pages)(struct vm_fault___6 *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct___6 *);
	vm_fault_t (*page_mkwrite)(struct vm_fault___6 *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault___6 *);
	int (*access)(struct vm_area_struct___6 *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct___6 *);
	int (*set_policy)(struct vm_area_struct___6 *, struct mempolicy *);
	struct mempolicy * (*get_policy)(struct vm_area_struct___6 *, long unsigned int);
	struct page___6 * (*find_special_page)(struct vm_area_struct___6 *, long unsigned int);
};

struct vm_fault___6 {
	const struct {
		struct vm_area_struct___6 *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page___6 *cow_page;
	struct page___6 *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t___6 prealloc_pte;
};

struct lruvec___6;

struct lru_gen_mm_walk___6 {
	struct lruvec___6 *lruvec;
	long unsigned int max_seq;
	long unsigned int next_addr;
	int nr_pages[40];
	int mm_stats[6];
	int batched;
	bool can_swap;
	bool force_scan;
};

struct pglist_data___6;

struct lruvec___6 {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
	struct lru_gen_struct lrugen;
	struct lru_gen_mm_state mm_state;
	struct pglist_data___6 *pgdat;
};

struct zone___6 {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long int lowmem_reserve[5];
	int node;
	struct pglist_data___6 *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high;
	int pageset_batch;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	long unsigned int present_early_pages;
	long unsigned int cma_pages;
	const char *name;
	long unsigned int nr_isolate_pageblock;
	seqlock_t span_seqlock;
	int initialized;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct free_area free_area[11];
	long unsigned int flags;
	spinlock_t lock;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int percpu_drift_mark;
	long unsigned int compact_cached_free_pfn;
	long unsigned int compact_cached_migrate_pfn[2];
	long unsigned int compact_init_migrate_pfn;
	long unsigned int compact_init_free_pfn;
	unsigned int compact_considered;
	unsigned int compact_defer_shift;
	int compact_order_failed;
	bool compact_blockskip_flush;
	bool contiguous;
	short: 16;
	struct cacheline_padding _pad3_;
	atomic_long_t vm_stat[11];
	atomic_long_t vm_numa_event[6];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct zoneref___6 {
	struct zone___6 *zone;
	int zone_idx;
};

struct zonelist___6 {
	struct zoneref___6 _zonerefs[5121];
};

struct pglist_data___6 {
	struct zone___6 node_zones[5];
	struct zonelist___6 node_zonelists[2];
	int nr_zones;
	spinlock_t node_size_lock;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct mutex kswapd_lock;
	struct task_struct___6 *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct___6 *kcompactd;
	bool proactive_compact_trigger;
	long unsigned int totalreserve_pages;
	long unsigned int min_unmapped_pages;
	long unsigned int min_slab_pages;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct deferred_split deferred_split_queue;
	unsigned int nbp_rl_start;
	long unsigned int nbp_rl_nr_cand;
	unsigned int nbp_threshold;
	unsigned int nbp_th_start;
	long unsigned int nbp_th_nr_cand;
	struct lruvec___6 __lruvec;
	long unsigned int flags;
	struct lru_gen_mm_walk___6 mm_walk;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[43];
	struct memory_tier *memtier;
	long: 64;
	long: 64;
	long: 64;
};

struct core_state___6;

struct signal_struct___6 {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct___6 *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct___6 *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state___6 *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	int posix_timer_id;
	struct list_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid___2 *pids[4];
	atomic_t tick_dep_mask;
	struct pid___2 *tty_old_pgrp;
	int leader;
	struct tty_struct___2 *tty;
	struct autogroup *autogroup;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	unsigned int audit_tty;
	struct tty_audit_buf *tty_audit_buf;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct___6 *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct net___6;

struct nsproxy___6 {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net___6 *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct bio___6;

struct bio_list___6 {
	struct bio___6 *head;
	struct bio___6 *tail;
};

struct bdi_writeback___6 {
	struct backing_dev_info___6 *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	long unsigned int dirty_sleep;
	struct list_head bdi_node;
	struct percpu_ref refcnt;
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css;
	struct cgroup_subsys_state *blkcg_css;
	struct list_head memcg_node;
	struct list_head blkcg_node;
	struct list_head b_attached;
	struct list_head offline_node;
	union {
		struct work_struct release_work;
		struct callback_head rcu;
	};
};

struct backing_dev_info___6 {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	struct bdi_writeback___6 wb;
	struct list_head wb_list;
	struct xarray cgwb_tree;
	struct mutex cgwb_release_mutex;
	struct rw_semaphore wb_switch_rwsem;
	wait_queue_head_t wb_waitq;
	struct device___6 *dev;
	char dev_name[64];
	struct device___6 *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry___6 *debug_dir;
};

struct cgroup___6;

struct css_set___6 {
	struct cgroup_subsys_state *subsys[13];
	refcount_t refcount;
	struct css_set___6 *dom_cset;
	struct cgroup___6 *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[13];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_src_preload_node;
	struct list_head mg_dst_preload_node;
	struct list_head mg_node;
	struct cgroup___6 *mg_src_cgrp;
	struct cgroup___6 *mg_dst_cgrp;
	struct css_set___6 *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
};

struct fasync_struct___6;

struct pipe_buffer___6;

struct pipe_inode_info___6 {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	bool note_loss;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	struct page___6 *tmp_page;
	struct fasync_struct___6 *fasync_readers;
	struct fasync_struct___6 *fasync_writers;
	struct pipe_buffer___6 *bufs;
	struct user_struct *user;
	struct watch_queue *watch_queue;
};

struct vm_struct___6 {
	struct vm_struct___6 *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page___6 **pages;
	unsigned int page_order;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

struct cgroup___6 {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	struct kernfs_node___6 *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	struct cgroup_file psi_files[4];
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[13];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[13];
	struct cgroup___6 *dom_cgrp;
	struct cgroup___6 *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group *psi;
	struct cgroup_bpf bpf;
	atomic_t congestion_count;
	struct cgroup_freezer_state freezer;
	struct cgroup___6 *ancestors[0];
};

struct core_thread___6 {
	struct task_struct___6 *task;
	struct core_thread___6 *next;
};

struct core_state___6 {
	atomic_t nr_threads;
	struct core_thread___6 dumper;
	struct completion startup;
};

struct kiocb___6 {
	struct file___6 *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb___6 *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	struct wait_page_queue *ki_waitq;
};

struct iattr___6 {
	unsigned int ia_valid;
	umode_t ia_mode;
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file___6 *ia_file;
};

struct dquot___6 {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block___6 *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};

struct quota_format_type___6 {
	int qf_fmt_id;
	const struct quota_format_ops___6 *qf_ops;
	struct module___6 *qf_owner;
	struct quota_format_type___6 *qf_next;
};

struct quota_format_ops___6 {
	int (*check_quota_file)(struct super_block___6 *, int);
	int (*read_file_info)(struct super_block___6 *, int);
	int (*write_file_info)(struct super_block___6 *, int);
	int (*free_file_info)(struct super_block___6 *, int);
	int (*read_dqblk)(struct dquot___6 *);
	int (*commit_dqblk)(struct dquot___6 *);
	int (*release_dqblk)(struct dquot___6 *);
	int (*get_next_id)(struct super_block___6 *, struct kqid *);
};

struct dquot_operations___6 {
	int (*write_dquot)(struct dquot___6 *);
	struct dquot___6 * (*alloc_dquot)(struct super_block___6 *, int);
	void (*destroy_dquot)(struct dquot___6 *);
	int (*acquire_dquot)(struct dquot___6 *);
	int (*release_dquot)(struct dquot___6 *);
	int (*mark_dirty)(struct dquot___6 *);
	int (*write_info)(struct super_block___6 *, int);
	qsize_t * (*get_reserved_space)(struct inode___6 *);
	int (*get_projid)(struct inode___6 *, kprojid_t *);
	int (*get_inode_usage)(struct inode___6 *, qsize_t *);
	int (*get_next_id)(struct super_block___6 *, struct kqid *);
};

struct quotactl_ops___6 {
	int (*quota_on)(struct super_block___6 *, int, int, const struct path___6 *);
	int (*quota_off)(struct super_block___6 *, int);
	int (*quota_enable)(struct super_block___6 *, unsigned int);
	int (*quota_disable)(struct super_block___6 *, unsigned int);
	int (*quota_sync)(struct super_block___6 *, int);
	int (*set_info)(struct super_block___6 *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block___6 *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block___6 *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block___6 *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block___6 *, struct qc_state *);
	int (*rm_xquota)(struct super_block___6 *, unsigned int);
};

struct writeback_control___6;

struct address_space_operations___6 {
	int (*writepage)(struct page___6 *, struct writeback_control___6 *);
	int (*read_folio)(struct file___6 *, struct folio___6 *);
	int (*writepages)(struct address_space___6 *, struct writeback_control___6 *);
	bool (*dirty_folio)(struct address_space___6 *, struct folio___6 *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file___6 *, struct address_space___6 *, loff_t, unsigned int, struct page___6 **, void **);
	int (*write_end)(struct file___6 *, struct address_space___6 *, loff_t, unsigned int, unsigned int, struct page___6 *, void *);
	sector_t (*bmap)(struct address_space___6 *, sector_t);
	void (*invalidate_folio)(struct folio___6 *, size_t, size_t);
	bool (*release_folio)(struct folio___6 *, gfp_t);
	void (*free_folio)(struct folio___6 *);
	ssize_t (*direct_IO)(struct kiocb___6 *, struct iov_iter___6 *);
	int (*migrate_folio)(struct address_space___6 *, struct folio___6 *, struct folio___6 *, enum migrate_mode);
	int (*launder_folio)(struct folio___6 *);
	bool (*is_partially_uptodate)(struct folio___6 *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio___6 *, bool *, bool *);
	int (*error_remove_page)(struct address_space___6 *, struct page___6 *);
	int (*swap_activate)(struct swap_info_struct *, struct file___6 *, sector_t *);
	void (*swap_deactivate)(struct file___6 *);
	int (*swap_rw)(struct kiocb___6 *, struct iov_iter___6 *);
};

struct writeback_control___6 {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_fscache_wb: 1;
	unsigned int no_cgroup_owner: 1;
	unsigned int punt_to_cgroup: 1;
	struct swap_iocb **swap_plug;
	struct bdi_writeback___6 *wb;
	struct inode___6 *inode;
	int wb_id;
	int wb_lcand_id;
	int wb_tcand_id;
	size_t wb_bytes;
	size_t wb_lcand_bytes;
	size_t wb_tcand_bytes;
};

struct bio_vec___6;

struct iov_iter___6 {
	u8 iter_type;
	bool nofault;
	bool data_source;
	bool user_backed;
	union {
		size_t iov_offset;
		int last_offset;
	};
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec___6 *bvec;
		struct xarray *xarray;
		struct pipe_inode_info___6 *pipe;
		void *ubuf;
	};
	union {
		long unsigned int nr_segs;
		struct {
			unsigned int head;
			unsigned int start_head;
		};
		loff_t xarray_start;
	};
};

struct inode_operations___6 {
	struct dentry___6 * (*lookup)(struct inode___6 *, struct dentry___6 *, unsigned int);
	const char * (*get_link)(struct dentry___6 *, struct inode___6 *, struct delayed_call *);
	int (*permission)(struct user_namespace *, struct inode___6 *, int);
	struct posix_acl * (*get_acl)(struct inode___6 *, int, bool);
	int (*readlink)(struct dentry___6 *, char *, int);
	int (*create)(struct user_namespace *, struct inode___6 *, struct dentry___6 *, umode_t, bool);
	int (*link)(struct dentry___6 *, struct inode___6 *, struct dentry___6 *);
	int (*unlink)(struct inode___6 *, struct dentry___6 *);
	int (*symlink)(struct user_namespace *, struct inode___6 *, struct dentry___6 *, const char *);
	int (*mkdir)(struct user_namespace *, struct inode___6 *, struct dentry___6 *, umode_t);
	int (*rmdir)(struct inode___6 *, struct dentry___6 *);
	int (*mknod)(struct user_namespace *, struct inode___6 *, struct dentry___6 *, umode_t, dev_t);
	int (*rename)(struct user_namespace *, struct inode___6 *, struct dentry___6 *, struct inode___6 *, struct dentry___6 *, unsigned int);
	int (*setattr)(struct user_namespace *, struct dentry___6 *, struct iattr___6 *);
	int (*getattr)(struct user_namespace *, const struct path___6 *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry___6 *, char *, size_t);
	int (*fiemap)(struct inode___6 *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode___6 *, struct timespec64 *, int);
	int (*atomic_open)(struct inode___6 *, struct dentry___6 *, struct file___6 *, unsigned int, umode_t);
	int (*tmpfile)(struct user_namespace *, struct inode___6 *, struct file___6 *, umode_t);
	int (*set_acl)(struct user_namespace *, struct inode___6 *, struct posix_acl *, int);
	int (*fileattr_set)(struct user_namespace *, struct dentry___6 *, struct fileattr *);
	int (*fileattr_get)(struct dentry___6 *, struct fileattr *);
	long: 64;
};

struct file_lock_operations___6 {
	void (*fl_copy_lock)(struct file_lock___6 *, struct file_lock___6 *);
	void (*fl_release_private)(struct file_lock___6 *);
};

struct lock_manager_operations___6;

struct file_lock___6 {
	struct file_lock___6 *fl_blocker;
	struct list_head fl_list;
	struct hlist_node fl_link;
	struct list_head fl_blocked_requests;
	struct list_head fl_blocked_member;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	unsigned int fl_pid;
	int fl_link_cpu;
	wait_queue_head_t fl_wait;
	struct file___6 *fl_file;
	loff_t fl_start;
	loff_t fl_end;
	struct fasync_struct___6 *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct file_lock_operations___6 *fl_ops;
	const struct lock_manager_operations___6 *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
	} fl_u;
};

struct lock_manager_operations___6 {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock___6 *);
	int (*lm_grant)(struct file_lock___6 *, int);
	bool (*lm_break)(struct file_lock___6 *);
	int (*lm_change)(struct file_lock___6 *, int, struct list_head *);
	void (*lm_setup)(struct file_lock___6 *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lock___6 *);
	bool (*lm_lock_expirable)(struct file_lock___6 *);
	void (*lm_expire_lock)();
};

struct fasync_struct___6 {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct___6 *fa_next;
	struct file___6 *fa_file;
	struct callback_head fa_rcu;
};

struct super_operations___6 {
	struct inode___6 * (*alloc_inode)(struct super_block___6 *);
	void (*destroy_inode)(struct inode___6 *);
	void (*free_inode)(struct inode___6 *);
	void (*dirty_inode)(struct inode___6 *, int);
	int (*write_inode)(struct inode___6 *, struct writeback_control___6 *);
	int (*drop_inode)(struct inode___6 *);
	void (*evict_inode)(struct inode___6 *);
	void (*put_super)(struct super_block___6 *);
	int (*sync_fs)(struct super_block___6 *, int);
	int (*freeze_super)(struct super_block___6 *);
	int (*freeze_fs)(struct super_block___6 *);
	int (*thaw_super)(struct super_block___6 *);
	int (*unfreeze_fs)(struct super_block___6 *);
	int (*statfs)(struct dentry___6 *, struct kstatfs *);
	int (*remount_fs)(struct super_block___6 *, int *, char *);
	void (*umount_begin)(struct super_block___6 *);
	int (*show_options)(struct seq_file___6 *, struct dentry___6 *);
	int (*show_devname)(struct seq_file___6 *, struct dentry___6 *);
	int (*show_path)(struct seq_file___6 *, struct dentry___6 *);
	int (*show_stats)(struct seq_file___6 *, struct dentry___6 *);
	ssize_t (*quota_read)(struct super_block___6 *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block___6 *, int, const char *, size_t, loff_t);
	struct dquot___6 ** (*get_dquots)(struct inode___6 *);
	long int (*nr_cached_objects)(struct super_block___6 *, struct shrink_control___6 *);
	long int (*free_cached_objects)(struct super_block___6 *, struct shrink_control___6 *);
};

struct wakeup_source___6;

struct dev_pm_info___6 {
	pm_message_t power_state;
	unsigned int can_wakeup: 1;
	unsigned int async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	struct list_head entry;
	struct completion completion;
	struct wakeup_source___6 *wakeup;
	bool wakeup_path: 1;
	bool syscore: 1;
	bool no_pm_callbacks: 1;
	unsigned int must_resume: 1;
	unsigned int may_skip_resume: 1;
	struct hrtimer suspend_timer;
	u64 timer_expires;
	struct work_struct work;
	wait_queue_head_t wait_queue;
	struct wake_irq *wakeirq;
	atomic_t usage_count;
	atomic_t child_count;
	unsigned int disable_depth: 3;
	unsigned int idle_notification: 1;
	unsigned int request_pending: 1;
	unsigned int deferred_resume: 1;
	unsigned int needs_force_resume: 1;
	unsigned int runtime_auto: 1;
	bool ignore_children: 1;
	unsigned int no_callbacks: 1;
	unsigned int irq_safe: 1;
	unsigned int use_autosuspend: 1;
	unsigned int timer_autosuspends: 1;
	unsigned int memalloc_noio: 1;
	unsigned int links_count;
	enum rpm_request request;
	enum rpm_status runtime_status;
	enum rpm_status last_status;
	int runtime_error;
	int autosuspend_delay;
	u64 last_busy;
	u64 active_time;
	u64 suspended_time;
	u64 accounting_timestamp;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device___6 *, s32);
	struct dev_pm_qos *qos;
};

struct device_type___6;

struct bus_type___6;

struct device_driver___6;

struct dev_pm_domain___6;

struct fwnode_handle___6;

struct class___6;

struct device___6 {
	struct kobject___6 kobj;
	struct device___6 *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type___6 *type;
	struct bus_type___6 *bus;
	struct device_driver___6 *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info___6 power;
	struct dev_pm_domain___6 *pm_domain;
	struct em_perf_domain *em_pd;
	struct dev_pin_info *pins;
	struct dev_msi_info msi;
	const struct dma_map_ops *dma_ops;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct cma *cma_area;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle___6 *fwnode;
	int numa_node;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	struct class___6 *class;
	const struct attribute_group___6 **groups;
	void (*release)(struct device___6 *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
};

struct block_device___6 {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	bool bd_read_only;
	dev_t bd_dev;
	atomic_t bd_openers;
	struct inode___6 *bd_inode;
	struct super_block___6 *bd_super;
	void *bd_claiming;
	struct device___6 bd_device;
	void *bd_holder;
	int bd_holders;
	bool bd_write_holder;
	struct kobject___6 *bd_holder_dir;
	u8 bd_partno;
	spinlock_t bd_size_lock;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	int bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct super_block___6 *bd_fsfreeze_sb;
	struct partition_meta_info *bd_meta_info;
};

typedef void (*poll_queue_proc___6)(struct file___6 *, wait_queue_head_t *, struct poll_table_struct___6 *);

struct poll_table_struct___6 {
	poll_queue_proc___6 _qproc;
	__poll_t _key;
};

struct seq_file___6 {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations___6 *op;
	int poll_event;
	const struct file___6 *file;
	void *private;
};

typedef void bio_end_io_t___6(struct bio___6 *);

struct bio_vec___6 {
	struct page___6 *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct bio___6 {
	struct bio___6 *bi_next;
	struct block_device___6 *bi_bdev;
	blk_opf_t bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t___6 *bi_end_io;
	void *bi_private;
	struct blkcg_gq *bi_blkg;
	struct bio_issue bi_issue;
	u64 bi_iocost_cost;
	struct bio_crypt_ctx *bi_crypt_context;
	union {
		struct bio_integrity_payload *bi_integrity;
	};
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec___6 *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec___6 bi_inline_vecs[0];
};

struct dev_pagemap_ops___6 {
	void (*page_free)(struct page___6 *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault___6 *);
	int (*memory_failure)(struct dev_pagemap___6 *, long unsigned int, long unsigned int, int);
};

struct ubuf_info___6;

struct sock___6;

struct sk_buff___6;

struct msghdr___6 {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter___6 msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb___6 *msg_iocb;
	struct ubuf_info___6 *msg_ubuf;
	int (*sg_from_iter)(struct sock___6 *, struct sk_buff___6 *, struct iov_iter___6 *, size_t);
};

struct ubuf_info___6 {
	void (*callback)(struct sk_buff___6 *, struct ubuf_info___6 *, bool);
	refcount_t refcnt;
	u8 flags;
};

struct sk_buff_list___6 {
	struct sk_buff___6 *next;
	struct sk_buff___6 *prev;
};

struct sk_buff_head___6 {
	union {
		struct {
			struct sk_buff___6 *next;
			struct sk_buff___6 *prev;
		};
		struct sk_buff_list___6 list;
	};
	__u32 qlen;
	spinlock_t lock;
};

struct socket___6;

struct net_device___6;

struct sock___6 {
	struct sock_common __sk_common;
	struct dst_entry *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	socket_lock_t sk_lock;
	atomic_t sk_drops;
	int sk_rcvlowat;
	struct sk_buff_head___6 sk_error_queue;
	struct sk_buff_head___6 sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	int sk_forward_alloc;
	u32 sk_reserved_mem;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	int sk_rcvbuf;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	struct xfrm_policy *sk_policy[2];
	struct dst_entry *sk_dst_cache;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head___6 sk_write_queue;
	__s32 sk_peek_off;
	int sk_write_pending;
	__u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	long int sk_sndtimeo;
	struct timer_list sk_timer;
	__u32 sk_priority;
	__u32 sk_mark;
	long unsigned int sk_pacing_rate;
	long unsigned int sk_max_pacing_rate;
	struct page_frag___6 sk_frag;
	netdev_features_t sk_route_caps;
	int sk_gso_type;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	__u32 sk_txhash;
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_userlocks: 4;
	u8 sk_pacing_shift;
	u16 sk_type;
	u16 sk_protocol;
	u16 sk_gso_max_segs;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	u8 sk_txrehash;
	u8 sk_prefer_busy_poll;
	u16 sk_busy_poll_budget;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid___2 *sk_peer_pid;
	const struct cred *sk_peer_cred;
	long int sk_rcvtimeo;
	ktime_t sk_stamp;
	u16 sk_tsflags;
	u8 sk_shutdown;
	atomic_t sk_tskey;
	atomic_t sk_zckey;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	struct socket___6 *sk_socket;
	void *sk_user_data;
	void *sk_security;
	struct sock_cgroup_data sk_cgrp_data;
	struct mem_cgroup___6 *sk_memcg;
	void (*sk_state_change)(struct sock___6 *);
	void (*sk_data_ready)(struct sock___6 *);
	void (*sk_write_space)(struct sock___6 *);
	void (*sk_error_report)(struct sock___6 *);
	int (*sk_backlog_rcv)(struct sock___6 *, struct sk_buff___6 *);
	struct sk_buff___6 * (*sk_validate_xmit_skb)(struct sock___6 *, struct net_device___6 *, struct sk_buff___6 *);
	void (*sk_destruct)(struct sock___6 *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
	struct hlist_node sk_bind2_node;
};

struct sk_buff___6 {
	union {
		struct {
			struct sk_buff___6 *next;
			struct sk_buff___6 *prev;
			union {
				struct net_device___6 *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	union {
		struct sock___6 *sk;
		int ip_defrag_offset;
	};
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff___6 *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};

struct socket_wq___6 {
	wait_queue_head_t wait;
	struct fasync_struct___6 *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
	long: 64;
};

struct proto_ops___6;

struct socket___6 {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file___6 *file;
	struct sock___6 *sk;
	const struct proto_ops___6 *ops;
	long: 64;
	long: 64;
	long: 64;
	struct socket_wq___6 wq;
};

typedef int (*sk_read_actor_t___6)(read_descriptor_t *, struct sk_buff___6 *, unsigned int, size_t);

typedef int (*skb_read_actor_t___6)(struct sock___6 *, struct sk_buff___6 *);

struct proto_ops___6 {
	int family;
	struct module___6 *owner;
	int (*release)(struct socket___6 *);
	int (*bind)(struct socket___6 *, struct sockaddr *, int);
	int (*connect)(struct socket___6 *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket___6 *, struct socket___6 *);
	int (*accept)(struct socket___6 *, struct socket___6 *, int, bool);
	int (*getname)(struct socket___6 *, struct sockaddr *, int);
	__poll_t (*poll)(struct file___6 *, struct socket___6 *, struct poll_table_struct___6 *);
	int (*ioctl)(struct socket___6 *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct socket___6 *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket___6 *, void *, bool, bool);
	int (*listen)(struct socket___6 *, int);
	int (*shutdown)(struct socket___6 *, int);
	int (*setsockopt)(struct socket___6 *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket___6 *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file___6 *, struct socket___6 *);
	int (*sendmsg)(struct socket___6 *, struct msghdr___6 *, size_t);
	int (*recvmsg)(struct socket___6 *, struct msghdr___6 *, size_t, int);
	int (*mmap)(struct file___6 *, struct socket___6 *, struct vm_area_struct___6 *);
	ssize_t (*sendpage)(struct socket___6 *, struct page___6 *, int, size_t, int);
	ssize_t (*splice_read)(struct socket___6 *, loff_t *, struct pipe_inode_info___6 *, size_t, unsigned int);
	int (*set_peek_off)(struct sock___6 *, int);
	int (*peek_len)(struct socket___6 *);
	int (*read_sock)(struct sock___6 *, read_descriptor_t *, sk_read_actor_t___6);
	int (*read_skb)(struct sock___6 *, skb_read_actor_t___6);
	int (*sendpage_locked)(struct sock___6 *, struct page___6 *, int, size_t, int);
	int (*sendmsg_locked)(struct sock___6 *, struct msghdr___6 *, size_t);
	int (*set_rcvlowat)(struct sock___6 *, int);
};

struct net___6 {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	atomic_t dev_unreg_count;
	unsigned int dev_base_seq;
	int ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node cleanup_list;
	struct key_tag *key_domain;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
	struct sock___6 *rtnl;
	struct sock___6 *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device___6 *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_ipv4 ipv4;
	struct netns_ipv6 ipv6;
	struct netns_ieee802154_lowpan ieee802154_lowpan;
	struct netns_sctp sctp;
	struct netns_nf nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct netns_ft ft;
	struct sk_buff_head___6 wext_nlevents;
	struct net_generic *gen;
	struct netns_bpf bpf;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_xfrm xfrm;
	u64 net_cookie;
	struct netns_ipvs *ipvs;
	struct netns_mpls mpls;
	struct netns_can can;
	struct netns_xdp xdp;
	struct netns_mctp mctp;
	struct sock___6 *crypto_nlsk;
	struct sock___6 *diag_nlsk;
	struct netns_smc smc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct kernfs_elem_symlink___6 {
	struct kernfs_node___6 *target_kn;
};

struct kernfs_ops___6;

struct kernfs_elem_attr___6 {
	const struct kernfs_ops___6 *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node___6 *notify_next;
};

struct kernfs_node___6 {
	atomic_t count;
	atomic_t active;
	struct kernfs_node___6 *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink___6 symlink;
		struct kernfs_elem_attr___6 attr;
	};
	void *priv;
	u64 id;
	short unsigned int flags;
	umode_t mode;
	struct kernfs_iattrs *iattr;
};

struct kernfs_open_file___6;

struct kernfs_ops___6 {
	int (*open)(struct kernfs_open_file___6 *);
	void (*release)(struct kernfs_open_file___6 *);
	int (*seq_show)(struct seq_file___6 *, void *);
	void * (*seq_start)(struct seq_file___6 *, loff_t *);
	void * (*seq_next)(struct seq_file___6 *, void *, loff_t *);
	void (*seq_stop)(struct seq_file___6 *, void *);
	ssize_t (*read)(struct kernfs_open_file___6 *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file___6 *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file___6 *, struct poll_table_struct___6 *);
	int (*mmap)(struct kernfs_open_file___6 *, struct vm_area_struct___6 *);
};

struct kernfs_open_file___6 {
	struct kernfs_node___6 *kn;
	struct file___6 *file;
	struct seq_file___6 *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct___6 *vm_ops;
};

struct kobj_ns_type_operations___6 {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock___6 *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

struct bin_attribute___6 {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space___6 * (*f_mapping)();
	ssize_t (*read)(struct file___6 *, struct kobject___6 *, struct bin_attribute___6 *, char *, loff_t, size_t);
	ssize_t (*write)(struct file___6 *, struct kobject___6 *, struct bin_attribute___6 *, char *, loff_t, size_t);
	int (*mmap)(struct file___6 *, struct kobject___6 *, struct bin_attribute___6 *, struct vm_area_struct___6 *);
};

struct sysfs_ops___6 {
	ssize_t (*show)(struct kobject___6 *, struct attribute *, char *);
	ssize_t (*store)(struct kobject___6 *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops___6;

struct kset___6 {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject___6 kobj;
	const struct kset_uevent_ops___6 *uevent_ops;
};

struct kobj_type___6 {
	void (*release)(struct kobject___6 *);
	const struct sysfs_ops___6 *sysfs_ops;
	const struct attribute_group___6 **default_groups;
	const struct kobj_ns_type_operations___6 * (*child_ns_type)(struct kobject___6 *);
	const void * (*namespace)(struct kobject___6 *);
	void (*get_ownership)(struct kobject___6 *, kuid_t *, kgid_t *);
};

struct kset_uevent_ops___6 {
	int (* const filter)(struct kobject___6 *);
	const char * (* const name)(struct kobject___6 *);
	int (* const uevent)(struct kobject___6 *, struct kobj_uevent_env *);
};

struct dev_pm_ops___6 {
	int (*prepare)(struct device___6 *);
	void (*complete)(struct device___6 *);
	int (*suspend)(struct device___6 *);
	int (*resume)(struct device___6 *);
	int (*freeze)(struct device___6 *);
	int (*thaw)(struct device___6 *);
	int (*poweroff)(struct device___6 *);
	int (*restore)(struct device___6 *);
	int (*suspend_late)(struct device___6 *);
	int (*resume_early)(struct device___6 *);
	int (*freeze_late)(struct device___6 *);
	int (*thaw_early)(struct device___6 *);
	int (*poweroff_late)(struct device___6 *);
	int (*restore_early)(struct device___6 *);
	int (*suspend_noirq)(struct device___6 *);
	int (*resume_noirq)(struct device___6 *);
	int (*freeze_noirq)(struct device___6 *);
	int (*thaw_noirq)(struct device___6 *);
	int (*poweroff_noirq)(struct device___6 *);
	int (*restore_noirq)(struct device___6 *);
	int (*runtime_suspend)(struct device___6 *);
	int (*runtime_resume)(struct device___6 *);
	int (*runtime_idle)(struct device___6 *);
};

struct wakeup_source___6 {
	const char *name;
	int id;
	struct list_head entry;
	spinlock_t lock;
	struct wake_irq *wakeirq;
	struct timer_list timer;
	long unsigned int timer_expires;
	ktime_t total_time;
	ktime_t max_time;
	ktime_t last_time;
	ktime_t start_prevent_time;
	ktime_t prevent_sleep_time;
	long unsigned int event_count;
	long unsigned int active_count;
	long unsigned int relax_count;
	long unsigned int expire_count;
	long unsigned int wakeup_count;
	struct device___6 *dev;
	bool active: 1;
	bool autosleep_enabled: 1;
};

struct dev_pm_domain___6 {
	struct dev_pm_ops___6 ops;
	int (*start)(struct device___6 *);
	void (*detach)(struct device___6 *, bool);
	int (*activate)(struct device___6 *);
	void (*sync)(struct device___6 *);
	void (*dismiss)(struct device___6 *);
};

struct bus_type___6 {
	const char *name;
	const char *dev_name;
	struct device___6 *dev_root;
	const struct attribute_group___6 **bus_groups;
	const struct attribute_group___6 **dev_groups;
	const struct attribute_group___6 **drv_groups;
	int (*match)(struct device___6 *, struct device_driver___6 *);
	int (*uevent)(struct device___6 *, struct kobj_uevent_env *);
	int (*probe)(struct device___6 *);
	void (*sync_state)(struct device___6 *);
	void (*remove)(struct device___6 *);
	void (*shutdown)(struct device___6 *);
	int (*online)(struct device___6 *);
	int (*offline)(struct device___6 *);
	int (*suspend)(struct device___6 *, pm_message_t);
	int (*resume)(struct device___6 *);
	int (*num_vf)(struct device___6 *);
	int (*dma_configure)(struct device___6 *);
	void (*dma_cleanup)(struct device___6 *);
	const struct dev_pm_ops___6 *pm;
	const struct iommu_ops *iommu_ops;
	struct subsys_private *p;
	struct lock_class_key lock_key;
	bool need_parent_lock;
};

struct device_driver___6 {
	const char *name;
	struct bus_type___6 *bus;
	struct module___6 *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device___6 *);
	void (*sync_state)(struct device___6 *);
	int (*remove)(struct device___6 *);
	void (*shutdown)(struct device___6 *);
	int (*suspend)(struct device___6 *, pm_message_t);
	int (*resume)(struct device___6 *);
	const struct attribute_group___6 **groups;
	const struct attribute_group___6 **dev_groups;
	const struct dev_pm_ops___6 *pm;
	void (*coredump)(struct device___6 *);
	struct driver_private *p;
};

struct device_type___6 {
	const char *name;
	const struct attribute_group___6 **groups;
	int (*uevent)(struct device___6 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___6 *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device___6 *);
	const struct dev_pm_ops___6 *pm;
};

struct class___6 {
	const char *name;
	struct module___6 *owner;
	const struct attribute_group___6 **class_groups;
	const struct attribute_group___6 **dev_groups;
	struct kobject___6 *dev_kobj;
	int (*dev_uevent)(struct device___6 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___6 *, umode_t *);
	void (*class_release)(struct class___6 *);
	void (*dev_release)(struct device___6 *);
	int (*shutdown_pre)(struct device___6 *);
	const struct kobj_ns_type_operations___6 *ns_type;
	const void * (*namespace)(struct device___6 *);
	void (*get_ownership)(struct device___6 *, kuid_t *, kgid_t *);
	const struct dev_pm_ops___6 *pm;
	struct subsys_private *p;
};

struct kparam_array___6;

struct kernel_param___6 {
	const char *name;
	struct module___6 *mod;
	const struct kernel_param_ops___6 *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array___6 *arr;
	};
};

struct kparam_array___6 {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops___6 *ops;
	void *elem;
};

struct module_attribute___6 {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute___6 *, struct module_kobject___6 *, char *);
	ssize_t (*store)(struct module_attribute___6 *, struct module_kobject___6 *, const char *, size_t);
	void (*setup)(struct module___6 *, const char *);
	int (*test)(struct module___6 *);
	void (*free)(struct module___6 *);
};

struct fwnode_operations___6;

struct fwnode_handle___6 {
	struct fwnode_handle___6 *secondary;
	const struct fwnode_operations___6 *ops;
	struct device___6 *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

struct fwnode_reference_args___6;

struct fwnode_endpoint___6;

struct fwnode_operations___6 {
	struct fwnode_handle___6 * (*get)(struct fwnode_handle___6 *);
	void (*put)(struct fwnode_handle___6 *);
	bool (*device_is_available)(const struct fwnode_handle___6 *);
	const void * (*device_get_match_data)(const struct fwnode_handle___6 *, const struct device___6 *);
	bool (*device_dma_supported)(const struct fwnode_handle___6 *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle___6 *);
	bool (*property_present)(const struct fwnode_handle___6 *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle___6 *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle___6 *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle___6 *);
	const char * (*get_name_prefix)(const struct fwnode_handle___6 *);
	struct fwnode_handle___6 * (*get_parent)(const struct fwnode_handle___6 *);
	struct fwnode_handle___6 * (*get_next_child_node)(const struct fwnode_handle___6 *, struct fwnode_handle___6 *);
	struct fwnode_handle___6 * (*get_named_child_node)(const struct fwnode_handle___6 *, const char *);
	int (*get_reference_args)(const struct fwnode_handle___6 *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args___6 *);
	struct fwnode_handle___6 * (*graph_get_next_endpoint)(const struct fwnode_handle___6 *, struct fwnode_handle___6 *);
	struct fwnode_handle___6 * (*graph_get_remote_endpoint)(const struct fwnode_handle___6 *);
	struct fwnode_handle___6 * (*graph_get_port_parent)(struct fwnode_handle___6 *);
	int (*graph_parse_endpoint)(const struct fwnode_handle___6 *, struct fwnode_endpoint___6 *);
	void * (*iomap)(struct fwnode_handle___6 *, int);
	int (*irq_get)(const struct fwnode_handle___6 *, unsigned int);
	int (*add_links)(struct fwnode_handle___6 *);
};

struct fwnode_endpoint___6 {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle___6 *local_fwnode;
};

struct fwnode_reference_args___6 {
	struct fwnode_handle___6 *fwnode;
	unsigned int nargs;
	u64 args[8];
};

struct pipe_buf_operations___6;

struct pipe_buffer___6 {
	struct page___6 *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations___6 *ops;
	unsigned int flags;
	long unsigned int private;
};

struct pipe_buf_operations___6 {
	int (*confirm)(struct pipe_inode_info___6 *, struct pipe_buffer___6 *);
	void (*release)(struct pipe_inode_info___6 *, struct pipe_buffer___6 *);
	bool (*try_steal)(struct pipe_inode_info___6 *, struct pipe_buffer___6 *);
	bool (*get)(struct pipe_inode_info___6 *, struct pipe_buffer___6 *);
};

typedef rx_handler_result_t rx_handler_func_t___6(struct sk_buff___6 **);

struct net_device___6 {
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
	long unsigned int state;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct list_head ptype_specific;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	unsigned int flags;
	long long unsigned int priv_flags;
	const struct net_device_ops *netdev_ops;
	int ifindex;
	short unsigned int gflags;
	short unsigned int hard_header_len;
	unsigned int mtu;
	short unsigned int needed_headroom;
	short unsigned int needed_tailroom;
	netdev_features_t features;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	netdev_features_t gso_partial_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct iw_handler_def *wireless_handlers;
	struct iw_public_data *wireless_data;
	const struct ethtool_ops *ethtool_ops;
	const struct l3mdev_ops *l3mdev_ops;
	const struct ndisc_ops *ndisc_ops;
	const struct xfrmdev_ops *xfrmdev_ops;
	const struct tlsdev_ops *tlsdev_ops;
	const struct header_ops *header_ops;
	unsigned char operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	short unsigned int padded;
	spinlock_t addr_list_lock;
	int irq;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset___6 *queues_kset;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct inet6_dev *ip6_ptr;
	struct vlan_info *vlan_info;
	struct dsa_port *dsa_ptr;
	struct tipc_bearer *tipc_ptr;
	void *atalk_ptr;
	void *ax25_ptr;
	struct wireless_dev *ieee80211_ptr;
	struct wpan_dev *ieee802154_ptr;
	struct mpls_dev *mpls_ptr;
	struct mctp_dev *mctp_ptr;
	const unsigned char *dev_addr;
	struct netdev_rx_queue *_rx;
	unsigned int num_rx_queues;
	unsigned int real_num_rx_queues;
	struct bpf_prog *xdp_prog;
	long unsigned int gro_flush_timeout;
	int napi_defer_hard_irqs;
	unsigned int gro_max_size;
	rx_handler_func_t___6 *rx_handler;
	void *rx_handler_data;
	struct mini_Qdisc *miniq_ingress;
	struct netdev_queue *ingress_queue;
	struct nf_hook_entries *nf_hooks_ingress;
	unsigned char broadcast[32];
	struct cpu_rmap *rx_cpu_rmap;
	struct hlist_node index_hlist;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netdev_queue *_tx;
	unsigned int num_tx_queues;
	unsigned int real_num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct xps_dev_maps *xps_maps[2];
	struct mini_Qdisc *miniq_egress;
	struct nf_hook_entries *nf_hooks_egress;
	struct hlist_head qdisc_hash[16];
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	int *pcpu_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	enum {
		NETREG_UNINITIALIZED___6 = 0,
		NETREG_REGISTERED___6 = 1,
		NETREG_UNREGISTERING___6 = 2,
		NETREG_UNREGISTERED___6 = 3,
		NETREG_RELEASED___6 = 4,
		NETREG_DUMMY___6 = 5,
	} reg_state: 8;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED___6 = 0,
		RTNL_LINK_INITIALIZING___6 = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device___6 *);
	struct netpoll_info *npinfo;
	possible_net_t nd_net;
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	struct garp_port *garp_port;
	struct mrp_port *mrp_port;
	struct dm_hw_stat_delta *dm_private;
	struct device___6 dev;
	const struct attribute_group___6 *sysfs_groups[4];
	const struct attribute_group___6 *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	unsigned int gso_max_size;
	unsigned int tso_max_size;
	u16 gso_max_segs;
	u16 tso_max_segs;
	const struct dcbnl_rtnl_ops *dcbnl_ops;
	s16 num_tc;
	struct netdev_tc_txq tc_to_txq[16];
	u8 prio_tc_map[16];
	unsigned int fcoe_ddp_xid;
	struct netprio_map *priomap;
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	unsigned int wol_enabled: 1;
	unsigned int threaded: 1;
	struct list_head net_notifier_list;
	const struct macsec_ops *macsec_ops;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	long: 64;
	long: 64;
	long: 64;
};

enum {
	OVS_VXLAN_EXT_UNSPEC = 0,
	OVS_VXLAN_EXT_GBP = 1,
	__OVS_VXLAN_EXT_MAX = 2,
};

enum ovs_tunnel_key_attr {
	OVS_TUNNEL_KEY_ATTR_ID = 0,
	OVS_TUNNEL_KEY_ATTR_IPV4_SRC = 1,
	OVS_TUNNEL_KEY_ATTR_IPV4_DST = 2,
	OVS_TUNNEL_KEY_ATTR_TOS = 3,
	OVS_TUNNEL_KEY_ATTR_TTL = 4,
	OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT = 5,
	OVS_TUNNEL_KEY_ATTR_CSUM = 6,
	OVS_TUNNEL_KEY_ATTR_OAM = 7,
	OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS = 8,
	OVS_TUNNEL_KEY_ATTR_TP_SRC = 9,
	OVS_TUNNEL_KEY_ATTR_TP_DST = 10,
	OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS = 11,
	OVS_TUNNEL_KEY_ATTR_IPV6_SRC = 12,
	OVS_TUNNEL_KEY_ATTR_IPV6_DST = 13,
	OVS_TUNNEL_KEY_ATTR_PAD = 14,
	OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS = 15,
	OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE = 16,
	__OVS_TUNNEL_KEY_ATTR_MAX = 17,
};

struct ovs_key_mpls {
	__be32 mpls_lse;
};

struct ovs_key_ipv6_exthdrs {
	__u16 hdrs;
};

struct ovs_key_icmp {
	__u8 icmp_type;
	__u8 icmp_code;
};

struct ovs_key_icmpv6 {
	__u8 icmpv6_type;
	__u8 icmpv6_code;
};

struct ovs_key_arp {
	__be32 arp_sip;
	__be32 arp_tip;
	__be16 arp_op;
	__u8 arp_sha[6];
	__u8 arp_tha[6];
};

struct ovs_key_nd {
	__be32 nd_target[4];
	__u8 nd_sll[6];
	__u8 nd_tll[6];
};

struct ovs_key_ct_tuple_ipv4 {
	__be32 ipv4_src;
	__be32 ipv4_dst;
	__be16 src_port;
	__be16 dst_port;
	__u8 ipv4_proto;
};

struct ovs_key_ct_tuple_ipv6 {
	__be32 ipv6_src[4];
	__be32 ipv6_dst[4];
	__be16 src_port;
	__be16 dst_port;
	__u8 ipv6_proto;
};

enum ovs_nsh_key_attr {
	OVS_NSH_KEY_ATTR_UNSPEC = 0,
	OVS_NSH_KEY_ATTR_BASE = 1,
	OVS_NSH_KEY_ATTR_MD1 = 2,
	OVS_NSH_KEY_ATTR_MD2 = 3,
	__OVS_NSH_KEY_ATTR_MAX = 4,
};

struct ovs_nsh_key_md1 {
	__be32 context[4];
};

enum ovs_sample_attr {
	OVS_SAMPLE_ATTR_UNSPEC = 0,
	OVS_SAMPLE_ATTR_PROBABILITY = 1,
	OVS_SAMPLE_ATTR_ACTIONS = 2,
	__OVS_SAMPLE_ATTR_MAX = 3,
	OVS_SAMPLE_ATTR_ARG = 4,
};

enum ovs_hash_alg {
	OVS_HASH_ALG_L4 = 0,
};

enum ovs_check_pkt_len_attr {
	OVS_CHECK_PKT_LEN_ATTR_UNSPEC = 0,
	OVS_CHECK_PKT_LEN_ATTR_PKT_LEN = 1,
	OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER = 2,
	OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL = 3,
	__OVS_CHECK_PKT_LEN_ATTR_MAX = 4,
	OVS_CHECK_PKT_LEN_ATTR_ARG = 5,
};

enum ovs_dec_ttl_attr {
	OVS_DEC_TTL_ATTR_UNSPEC = 0,
	OVS_DEC_TTL_ATTR_ACTION = 1,
	__OVS_DEC_TTL_ATTR_MAX = 2,
};

struct ovs_len_tbl {
	int len;
	const struct ovs_len_tbl *next;
};

enum ovs_meter_cmd {
	OVS_METER_CMD_UNSPEC = 0,
	OVS_METER_CMD_FEATURES = 1,
	OVS_METER_CMD_SET = 2,
	OVS_METER_CMD_DEL = 3,
	OVS_METER_CMD_GET = 4,
};

enum ovs_meter_attr {
	OVS_METER_ATTR_UNSPEC = 0,
	OVS_METER_ATTR_ID = 1,
	OVS_METER_ATTR_KBPS = 2,
	OVS_METER_ATTR_STATS = 3,
	OVS_METER_ATTR_BANDS = 4,
	OVS_METER_ATTR_USED = 5,
	OVS_METER_ATTR_CLEAR = 6,
	OVS_METER_ATTR_MAX_METERS = 7,
	OVS_METER_ATTR_MAX_BANDS = 8,
	OVS_METER_ATTR_PAD = 9,
	__OVS_METER_ATTR_MAX = 10,
};

enum ovs_band_attr {
	OVS_BAND_ATTR_UNSPEC = 0,
	OVS_BAND_ATTR_TYPE = 1,
	OVS_BAND_ATTR_RATE = 2,
	OVS_BAND_ATTR_BURST = 3,
	OVS_BAND_ATTR_STATS = 4,
	__OVS_BAND_ATTR_MAX = 5,
};

enum ovs_meter_band_type {
	OVS_METER_BAND_TYPE_UNSPEC = 0,
	OVS_METER_BAND_TYPE_DROP = 1,
	__OVS_METER_BAND_TYPE_MAX = 2,
};

struct kset___7;

struct kobj_type___7;

struct kernfs_node___7;

struct kobject___7 {
	const char *name;
	struct list_head entry;
	struct kobject___7 *parent;
	struct kset___7 *kset;
	const struct kobj_type___7 *ktype;
	struct kernfs_node___7 *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct module___7;

struct module_kobject___7 {
	struct kobject___7 kobj;
	struct module___7 *mod;
	struct kobject___7 *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct mod_tree_node___7 {
	struct module___7 *mod;
	struct latch_tree_node node;
};

struct module_layout___7 {
	void *base;
	unsigned int size;
	unsigned int text_size;
	unsigned int ro_size;
	unsigned int ro_after_init_size;
	struct mod_tree_node___7 mtn;
};

struct module_attribute___7;

struct kernel_param___7;

struct bpf_raw_event_map___4;

struct trace_event_call___2;

struct module___7 {
	enum module_state state;
	struct list_head list;
	char name[56];
	struct module_kobject___7 mkobj;
	struct module_attribute___7 *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject___7 *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param___7 *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool sig_ok;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	struct module_layout___7 core_layout;
	struct module_layout___7 init_layout;
	struct mod_arch_specific arch;
	long unsigned int taints;
	unsigned int num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map___4 *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call___2 **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	int num_static_call_sites;
	struct static_call_site *static_call_sites;
	int num_kunit_suites;
	struct kunit_suite **kunit_suites;
	bool klp;
	bool klp_alive;
	struct klp_modinfo *klp_info;
	unsigned int printk_index_size;
	struct pi_entry **printk_index_start;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
};

struct dentry___7;

struct super_block___7;

struct file_system_type___7 {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry___7 * (*mount)(struct file_system_type___7 *, int, const char *, void *);
	void (*kill_sb)(struct super_block___7 *);
	struct module___7 *owner;
	struct file_system_type___7 *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

struct page___7;

typedef struct page___7 *pgtable_t___7;

struct address_space___7;

struct page_pool___7;

struct mm_struct___7;

struct dev_pagemap___7;

struct page___7 {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space___7 *mapping;
			long unsigned int index;
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool___7 *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			union {
				long unsigned int dma_addr_upper;
				atomic_long_t pp_frag_count;
			};
		};
		struct {
			long unsigned int compound_head;
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			atomic_t compound_pincount;
			unsigned int compound_nr;
		};
		struct {
			long unsigned int _compound_pad_1;
			long unsigned int _compound_pad_2;
			struct list_head deferred_list;
		};
		struct {
			long unsigned int _pt_pad_1;
			pgtable_t___7 pmd_huge_pte;
			long unsigned int _pt_pad_2;
			union {
				struct mm_struct___7 *pt_mm;
				atomic_t pt_frag_refcount;
			};
			spinlock_t ptl;
		};
		struct {
			struct dev_pagemap___7 *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	long unsigned int memcg_data;
};

struct kernel_param_ops___7 {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param___7 *);
	int (*get)(char *, const struct kernel_param___7 *);
	void (*free)(void *);
};

struct file___7;

struct kiocb___7;

struct iov_iter___7;

struct poll_table_struct___7;

struct vm_area_struct___7;

struct inode___7;

struct file_lock___7;

struct pipe_inode_info___7;

struct seq_file___7;

struct file_operations___7 {
	struct module___7 *owner;
	loff_t (*llseek)(struct file___7 *, loff_t, int);
	ssize_t (*read)(struct file___7 *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file___7 *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb___7 *, struct iov_iter___7 *);
	ssize_t (*write_iter)(struct kiocb___7 *, struct iov_iter___7 *);
	int (*iopoll)(struct kiocb___7 *, struct io_comp_batch *, unsigned int);
	int (*iterate)(struct file___7 *, struct dir_context *);
	int (*iterate_shared)(struct file___7 *, struct dir_context *);
	__poll_t (*poll)(struct file___7 *, struct poll_table_struct___7 *);
	long int (*unlocked_ioctl)(struct file___7 *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file___7 *, unsigned int, long unsigned int);
	int (*mmap)(struct file___7 *, struct vm_area_struct___7 *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode___7 *, struct file___7 *);
	int (*flush)(struct file___7 *, fl_owner_t);
	int (*release)(struct inode___7 *, struct file___7 *);
	int (*fsync)(struct file___7 *, loff_t, loff_t, int);
	int (*fasync)(int, struct file___7 *, int);
	int (*lock)(struct file___7 *, int, struct file_lock___7 *);
	ssize_t (*sendpage)(struct file___7 *, struct page___7 *, int, size_t, loff_t *, int);
	long unsigned int (*get_unmapped_area)(struct file___7 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file___7 *, int, struct file_lock___7 *);
	ssize_t (*splice_write)(struct pipe_inode_info___7 *, struct file___7 *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file___7 *, loff_t *, struct pipe_inode_info___7 *, size_t, unsigned int);
	int (*setlease)(struct file___7 *, long int, struct file_lock___7 **, void **);
	long int (*fallocate)(struct file___7 *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file___7 *, struct file___7 *);
	ssize_t (*copy_file_range)(struct file___7 *, loff_t, struct file___7 *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file___7 *, loff_t, struct file___7 *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file___7 *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

struct static_call_mod___4 {
	struct static_call_mod___4 *next;
	struct module___7 *mod;
	struct static_call_site *sites;
};

struct static_call_key___4 {
	void *func;
	union {
		long unsigned int type;
		struct static_call_mod___4 *mods;
		struct static_call_site *sites;
	};
};

struct perf_event___2;

struct thread_struct___2 {
	struct desc_struct tls_array[3];
	long unsigned int sp;
	short unsigned int es;
	short unsigned int ds;
	short unsigned int fsindex;
	short unsigned int gsindex;
	long unsigned int fsbase;
	long unsigned int gsbase;
	struct perf_event___2 *ptrace_bps[4];
	long unsigned int virtual_dr6;
	long unsigned int ptrace_dr7;
	long unsigned int cr2;
	long unsigned int trap_nr;
	long unsigned int error_code;
	struct io_bitmap *io_bitmap;
	long unsigned int iopl_emul;
	unsigned int iopl_warn: 1;
	unsigned int sig_on_uaccess_err: 1;
	u32 pkru;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct fpu fpu;
};

struct page_frag___7 {
	struct page___7 *page;
	__u32 offset;
	__u32 size;
};

struct pid___3;

struct nsproxy___7;

struct signal_struct___7;

struct bio_list___7;

struct backing_dev_info___7;

struct css_set___7;

struct perf_event_context___2;

struct mem_cgroup___7;

struct vm_struct___7;

struct task_struct___7 {
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct___7 *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	const struct sched_class *sched_class;
	struct rb_node core_node;
	long unsigned int core_cookie;
	unsigned int core_occupation;
	struct task_group *sched_task_group;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_statistics stats;
	struct hlist_head preempt_notifiers;
	unsigned int btrace_seq;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct___7 *mm;
	struct mm_struct___7 *active_mm;
	struct task_rss_stat rss_stat;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	unsigned int sched_psi_wake_requeue: 1;
	int: 28;
	unsigned int sched_remote_wakeup: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int in_user_fault: 1;
	unsigned int in_lru_fault: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_page_owner: 1;
	unsigned int in_eventfd: 1;
	unsigned int pasid_activated: 1;
	unsigned int reported_split_lock: 1;
	unsigned int in_thrashing: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct___7 *real_parent;
	struct task_struct___7 *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct___7 *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid___3 *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_group;
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	struct vtime vtime;
	atomic_t tick_dep_mask;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	struct posix_cputimers_work posix_cputimers_work;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy___7 *nsproxy;
	struct signal_struct___7 *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct audit_context *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct___7 *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	void *journal_info;
	struct bio_list___7 *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct backing_dev_info___7 *backing_dev_info;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	unsigned int psi_flags;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
	struct css_set___7 *cgroups;
	struct list_head cg_list;
	u32 closid;
	u32 rmid;
	struct robust_list_head *robust_list;
	struct compat_robust_list_head *compat_robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	struct perf_event_context___2 *perf_event_ctxp[2];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	long unsigned int preempt_disable_ip;
	struct mempolicy *mempolicy;
	short int il_prev;
	short int pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	long unsigned int numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct numa_group *numa_group;
	long unsigned int *numa_faults;
	long unsigned int total_numa_faults;
	long unsigned int numa_faults_locality[3];
	long unsigned int numa_pages_migrated;
	struct rseq *rseq;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	struct tlbflush_unmap_batch tlb_ubc;
	union {
		refcount_t rcu_users;
		struct callback_head rcu;
	};
	struct pipe_inode_info___7 *splice_pipe;
	struct page_frag___7 task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	int latency_record_count;
	struct latency_record latency_record[32];
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	struct kunit *kunit_test;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace_recursion;
	struct mem_cgroup___7 *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup___7 *active_memcg;
	struct request_queue *throttle_queue;
	struct uprobe_task *utask;
	unsigned int sequential_io;
	unsigned int sequential_io_avg;
	struct kmap_ctrl kmap_ctrl;
	int pagefault_disabled;
	struct task_struct___7 *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct___7 *stack_vm_area;
	refcount_t stack_refcount;
	int patch_state;
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	void *mce_vaddr;
	__u64 mce_kflags;
	u64 mce_addr;
	__u64 mce_ripv: 1;
	__u64 mce_whole_page: 1;
	__u64 __mce_reserved: 62;
	struct callback_head mce_kill_me;
	int mce_count;
	struct llist_head kretprobe_instances;
	struct llist_head rethooks;
	struct callback_head l1d_flush_kill;
	union rv_task_monitor rv[1];
	struct thread_struct___2 thread;
};

struct mm_struct___7 {
	struct {
		struct maple_tree mm_mt;
		long unsigned int (*get_unmapped_area)(struct file___7 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int mmap_compat_base;
		long unsigned int mmap_compat_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		atomic_t mm_count;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[48];
		struct mm_rss_stat rss_stat;
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct___7 *owner;
		struct user_namespace *user_ns;
		struct file___7 *exe_file;
		struct mmu_notifier_subscriptions *notifier_subscriptions;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		atomic_t tlb_flush_batched;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		u32 pasid;
		long unsigned int ksm_merging_pages;
		long unsigned int ksm_rmap_items;
		struct {
			struct list_head list;
			long unsigned int bitmap;
			struct mem_cgroup___7 *memcg;
		} lru_gen;
	};
	long unsigned int cpu_bitmap[0];
};

struct vm_operations_struct___7;

struct vm_area_struct___7 {
	long unsigned int vm_start;
	long unsigned int vm_end;
	struct mm_struct___7 *vm_mm;
	pgprot_t vm_page_prot;
	long unsigned int vm_flags;
	union {
		struct {
			struct rb_node rb;
			long unsigned int rb_subtree_last;
		} shared;
		struct anon_vma_name *anon_name;
	};
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct___7 *vm_ops;
	long unsigned int vm_pgoff;
	struct file___7 *vm_file;
	void *vm_private_data;
	atomic_long_t swap_readahead_info;
	struct mempolicy *vm_policy;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

struct bin_attribute___7;

struct attribute_group___7 {
	const char *name;
	umode_t (*is_visible)(struct kobject___7 *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject___7 *, struct bin_attribute___7 *, int);
	struct attribute **attrs;
	struct bin_attribute___7 **bin_attrs;
};

struct tracepoint___4 {
	const char *name;
	struct static_key key;
	struct static_call_key___4 *static_call_key;
	void *static_call_tramp;
	void *iterator;
	int (*regfunc)();
	void (*unregfunc)();
	struct tracepoint_func *funcs;
};

struct bpf_raw_event_map___4 {
	struct tracepoint___4 *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	long: 64;
};

struct seq_operations___7 {
	void * (*start)(struct seq_file___7 *, loff_t *);
	void (*stop)(struct seq_file___7 *, void *);
	void * (*next)(struct seq_file___7 *, void *, loff_t *);
	int (*show)(struct seq_file___7 *, void *);
};

typedef void (*perf_overflow_handler_t___2)(struct perf_event___2 *, struct perf_sample_data *, struct pt_regs *);

struct fasync_struct___7;

struct pid_namespace___3;

struct perf_event___2 {
	struct list_head event_entry;
	struct list_head sibling_list;
	struct list_head active_list;
	struct rb_node group_node;
	u64 group_index;
	struct list_head migrate_entry;
	struct hlist_node hlist_entry;
	struct list_head active_entry;
	int nr_siblings;
	int event_caps;
	int group_caps;
	struct perf_event___2 *group_leader;
	struct pmu *pmu;
	void *pmu_private;
	enum perf_event_state state;
	unsigned int attach_state;
	local64_t count;
	atomic64_t child_count;
	u64 total_time_enabled;
	u64 total_time_running;
	u64 tstamp;
	struct perf_event_attr attr;
	u16 header_size;
	u16 id_header_size;
	u16 read_size;
	struct hw_perf_event hw;
	struct perf_event_context___2 *ctx;
	atomic_long_t refcount;
	atomic64_t child_total_time_enabled;
	atomic64_t child_total_time_running;
	struct mutex child_mutex;
	struct list_head child_list;
	struct perf_event___2 *parent;
	int oncpu;
	int cpu;
	struct list_head owner_entry;
	struct task_struct___7 *owner;
	struct mutex mmap_mutex;
	atomic_t mmap_count;
	struct perf_buffer *rb;
	struct list_head rb_entry;
	long unsigned int rcu_batches;
	int rcu_pending;
	wait_queue_head_t waitq;
	struct fasync_struct___7 *fasync;
	unsigned int pending_wakeup;
	unsigned int pending_kill;
	unsigned int pending_disable;
	unsigned int pending_sigtrap;
	long unsigned int pending_addr;
	struct irq_work pending_irq;
	struct callback_head pending_task;
	unsigned int pending_work;
	atomic_t event_limit;
	struct perf_addr_filters_head addr_filters;
	struct perf_addr_filter_range *addr_filter_ranges;
	long unsigned int addr_filters_gen;
	struct perf_event___2 *aux_event;
	void (*destroy)(struct perf_event___2 *);
	struct callback_head callback_head;
	struct pid_namespace___3 *ns;
	u64 id;
	atomic64_t lost_samples;
	u64 (*clock)();
	perf_overflow_handler_t___2 overflow_handler;
	void *overflow_handler_context;
	perf_overflow_handler_t___2 orig_overflow_handler;
	struct bpf_prog *prog;
	u64 bpf_cookie;
	struct trace_event_call___2 *tp_event;
	struct event_filter *filter;
	struct ftrace_ops ftrace_ops;
	struct perf_cgroup *cgrp;
	void *security;
	struct list_head sb_list;
};

struct address_space_operations___7;

struct address_space___7 {
	struct inode___7 *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	struct rw_semaphore i_mmap_rwsem;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations___7 *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t private_lock;
	struct list_head private_list;
	void *private_data;
};

struct device___7;

struct page_pool_params___7 {
	unsigned int flags;
	unsigned int order;
	unsigned int pool_size;
	int nid;
	struct device___7 *dev;
	enum dma_data_direction dma_dir;
	unsigned int max_len;
	unsigned int offset;
	void (*init_callback)(struct page___7 *, void *);
	void *init_arg;
};

struct pp_alloc_cache___7 {
	u32 count;
	struct page___7 *cache[128];
};

struct page_pool___7 {
	struct page_pool_params___7 p;
	struct delayed_work release_dw;
	void (*disconnect)(void *);
	long unsigned int defer_start;
	long unsigned int defer_warn;
	u32 pages_state_hold_cnt;
	unsigned int frag_offset;
	struct page___7 *frag_page;
	long int frag_users;
	u32 xdp_mem_id;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct pp_alloc_cache___7 alloc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct ptr_ring ring;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct dev_pagemap_ops___7;

struct dev_pagemap___7 {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops___7 *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct range ranges[0];
	};
};

struct folio___7 {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space___7 *mapping;
			long unsigned int index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page___7 page;
	};
	long unsigned int _flags_1;
	long unsigned int __head;
	unsigned char _folio_dtor;
	unsigned char _folio_order;
	atomic_t _total_mapcount;
	atomic_t _pincount;
	unsigned int _folio_nr_pages;
};

struct vfsmount___7;

struct path___7 {
	struct vfsmount___7 *mnt;
	struct dentry___7 *dentry;
};

struct fown_struct___3 {
	rwlock_t lock;
	struct pid___3 *pid;
	enum pid_type pid_type;
	kuid_t uid;
	kuid_t euid;
	int signum;
};

struct file___7 {
	union {
		struct llist_node f_llist;
		struct callback_head f_rcuhead;
		unsigned int f_iocb_flags;
	};
	struct path___7 f_path;
	struct inode___7 *f_inode;
	const struct file_operations___7 *f_op;
	spinlock_t f_lock;
	atomic_long_t f_count;
	unsigned int f_flags;
	fmode_t f_mode;
	struct mutex f_pos_lock;
	loff_t f_pos;
	struct fown_struct___3 f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	u64 f_version;
	void *f_security;
	void *private_data;
	struct hlist_head *f_ep;
	struct address_space___7 *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};

struct vm_fault___7;

struct vm_operations_struct___7 {
	void (*open)(struct vm_area_struct___7 *);
	void (*close)(struct vm_area_struct___7 *);
	int (*may_split)(struct vm_area_struct___7 *, long unsigned int);
	int (*mremap)(struct vm_area_struct___7 *);
	int (*mprotect)(struct vm_area_struct___7 *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault___7 *);
	vm_fault_t (*huge_fault)(struct vm_fault___7 *, enum page_entry_size);
	vm_fault_t (*map_pages)(struct vm_fault___7 *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct___7 *);
	vm_fault_t (*page_mkwrite)(struct vm_fault___7 *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault___7 *);
	int (*access)(struct vm_area_struct___7 *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct___7 *);
	int (*set_policy)(struct vm_area_struct___7 *, struct mempolicy *);
	struct mempolicy * (*get_policy)(struct vm_area_struct___7 *, long unsigned int);
	struct page___7 * (*find_special_page)(struct vm_area_struct___7 *, long unsigned int);
};

struct mem_cgroup___7 {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct page_counter memory;
	union {
		struct page_counter swap;
		struct page_counter memsw;
	};
	struct page_counter kmem;
	struct page_counter tcpmem;
	struct work_struct high_work;
	long unsigned int zswap_max;
	long unsigned int soft_limit;
	struct vmpressure vmpressure;
	bool oom_group;
	bool oom_lock;
	int under_oom;
	int swappiness;
	int oom_kill_disable;
	struct cgroup_file events_file;
	struct cgroup_file events_local_file;
	struct cgroup_file swap_events_file;
	struct mutex thresholds_lock;
	struct mem_cgroup_thresholds thresholds;
	struct mem_cgroup_thresholds memsw_thresholds;
	struct list_head oom_notify;
	long unsigned int move_charge_at_immigrate;
	spinlock_t move_lock;
	long unsigned int move_lock_flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct memcg_vmstats *vmstats;
	atomic_long_t memory_events[9];
	atomic_long_t memory_events_local[9];
	long unsigned int socket_pressure;
	bool tcpmem_active;
	int tcpmem_pressure;
	int kmemcg_id;
	struct obj_cgroup *objcg;
	struct list_head objcg_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	atomic_t moving_account;
	struct task_struct___7 *move_lock_task;
	struct memcg_vmstats_percpu *vmstats_percpu;
	struct list_head cgwb_list;
	struct wb_domain cgwb_domain;
	struct memcg_cgwb_frn cgwb_frn[4];
	struct list_head event_list;
	spinlock_t event_list_lock;
	struct deferred_split deferred_split_queue;
	struct lru_gen_mm_list mm_list;
	struct mem_cgroup_per_node *nodeinfo[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct vm_fault___7 {
	const struct {
		struct vm_area_struct___7 *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page___7 *cow_page;
	struct page___7 *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t___7 prealloc_pte;
};

struct lruvec___7;

struct lru_gen_mm_walk___7 {
	struct lruvec___7 *lruvec;
	long unsigned int max_seq;
	long unsigned int next_addr;
	int nr_pages[40];
	int mm_stats[6];
	int batched;
	bool can_swap;
	bool force_scan;
};

struct pglist_data___7;

struct lruvec___7 {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
	struct lru_gen_struct lrugen;
	struct lru_gen_mm_state mm_state;
	struct pglist_data___7 *pgdat;
};

struct zone___7 {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long int lowmem_reserve[5];
	int node;
	struct pglist_data___7 *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high;
	int pageset_batch;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	long unsigned int present_early_pages;
	long unsigned int cma_pages;
	const char *name;
	long unsigned int nr_isolate_pageblock;
	seqlock_t span_seqlock;
	int initialized;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct free_area free_area[11];
	long unsigned int flags;
	spinlock_t lock;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int percpu_drift_mark;
	long unsigned int compact_cached_free_pfn;
	long unsigned int compact_cached_migrate_pfn[2];
	long unsigned int compact_init_migrate_pfn;
	long unsigned int compact_init_free_pfn;
	unsigned int compact_considered;
	unsigned int compact_defer_shift;
	int compact_order_failed;
	bool compact_blockskip_flush;
	bool contiguous;
	short: 16;
	struct cacheline_padding _pad3_;
	atomic_long_t vm_stat[11];
	atomic_long_t vm_numa_event[6];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct zoneref___7 {
	struct zone___7 *zone;
	int zone_idx;
};

struct zonelist___7 {
	struct zoneref___7 _zonerefs[5121];
};

struct pglist_data___7 {
	struct zone___7 node_zones[5];
	struct zonelist___7 node_zonelists[2];
	int nr_zones;
	spinlock_t node_size_lock;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct mutex kswapd_lock;
	struct task_struct___7 *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct___7 *kcompactd;
	bool proactive_compact_trigger;
	long unsigned int totalreserve_pages;
	long unsigned int min_unmapped_pages;
	long unsigned int min_slab_pages;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct deferred_split deferred_split_queue;
	unsigned int nbp_rl_start;
	long unsigned int nbp_rl_nr_cand;
	unsigned int nbp_threshold;
	unsigned int nbp_th_start;
	long unsigned int nbp_th_nr_cand;
	struct lruvec___7 __lruvec;
	long unsigned int flags;
	struct lru_gen_mm_walk___7 mm_walk;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[43];
	struct memory_tier *memtier;
	long: 64;
	long: 64;
	long: 64;
};

struct upid___3 {
	int nr;
	struct pid_namespace___3 *ns;
};

struct pid_namespace___3 {
	struct idr idr;
	struct callback_head rcu;
	unsigned int pid_allocated;
	struct task_struct___7 *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace___3 *parent;
	struct fs_pin *bacct;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	int reboot;
	struct ns_common ns;
};

struct pid___3 {
	refcount_t count;
	unsigned int level;
	spinlock_t lock;
	struct hlist_head tasks[4];
	struct hlist_head inodes;
	wait_queue_head_t wait_pidfd;
	struct callback_head rcu;
	struct upid___3 numbers[1];
};

struct core_state___7;

struct signal_struct___7 {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct___7 *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct___7 *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state___7 *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	int posix_timer_id;
	struct list_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid___3 *pids[4];
	atomic_t tick_dep_mask;
	struct pid___3 *tty_old_pgrp;
	int leader;
	struct tty_struct___2 *tty;
	struct autogroup *autogroup;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	unsigned int audit_tty;
	struct tty_audit_buf *tty_audit_buf;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct___7 *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct net___7;

struct nsproxy___7 {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace___3 *pid_ns_for_children;
	struct net___7 *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct bio___7;

struct bio_list___7 {
	struct bio___7 *head;
	struct bio___7 *tail;
};

struct bdi_writeback___7 {
	struct backing_dev_info___7 *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	long unsigned int dirty_sleep;
	struct list_head bdi_node;
	struct percpu_ref refcnt;
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css;
	struct cgroup_subsys_state *blkcg_css;
	struct list_head memcg_node;
	struct list_head blkcg_node;
	struct list_head b_attached;
	struct list_head offline_node;
	union {
		struct work_struct release_work;
		struct callback_head rcu;
	};
};

struct backing_dev_info___7 {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	struct bdi_writeback___7 wb;
	struct list_head wb_list;
	struct xarray cgwb_tree;
	struct mutex cgwb_release_mutex;
	struct rw_semaphore wb_switch_rwsem;
	wait_queue_head_t wb_waitq;
	struct device___7 *dev;
	char dev_name[64];
	struct device___7 *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry___7 *debug_dir;
};

struct cgroup___7;

struct css_set___7 {
	struct cgroup_subsys_state *subsys[13];
	refcount_t refcount;
	struct css_set___7 *dom_cset;
	struct cgroup___7 *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[13];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_src_preload_node;
	struct list_head mg_dst_preload_node;
	struct list_head mg_node;
	struct cgroup___7 *mg_src_cgrp;
	struct cgroup___7 *mg_dst_cgrp;
	struct css_set___7 *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
};

struct perf_event_context___2 {
	struct pmu *pmu;
	raw_spinlock_t lock;
	struct mutex mutex;
	struct list_head active_ctx_list;
	struct perf_event_groups pinned_groups;
	struct perf_event_groups flexible_groups;
	struct list_head event_list;
	struct list_head pinned_active;
	struct list_head flexible_active;
	int nr_events;
	int nr_active;
	int nr_user;
	int is_active;
	int nr_stat;
	int nr_freq;
	int rotate_disable;
	int rotate_necessary;
	refcount_t refcount;
	struct task_struct___7 *task;
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	struct perf_event_context___2 *parent_ctx;
	u64 parent_gen;
	u64 generation;
	int pin_count;
	int nr_cgroups;
	void *task_ctx_data;
	struct callback_head callback_head;
	local_t nr_pending;
};

struct pipe_buffer___7;

struct pipe_inode_info___7 {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	bool note_loss;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	struct page___7 *tmp_page;
	struct fasync_struct___7 *fasync_readers;
	struct fasync_struct___7 *fasync_writers;
	struct pipe_buffer___7 *bufs;
	struct user_struct *user;
	struct watch_queue *watch_queue;
};

struct vm_struct___7 {
	struct vm_struct___7 *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page___7 **pages;
	unsigned int page_order;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

struct kernfs_elem_symlink___7 {
	struct kernfs_node___7 *target_kn;
};

struct kernfs_ops___7;

struct kernfs_elem_attr___7 {
	const struct kernfs_ops___7 *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node___7 *notify_next;
};

struct kernfs_node___7 {
	atomic_t count;
	atomic_t active;
	struct kernfs_node___7 *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink___7 symlink;
		struct kernfs_elem_attr___7 attr;
	};
	void *priv;
	u64 id;
	short unsigned int flags;
	umode_t mode;
	struct kernfs_iattrs *iattr;
};

struct kernfs_open_file___7;

struct kernfs_ops___7 {
	int (*open)(struct kernfs_open_file___7 *);
	void (*release)(struct kernfs_open_file___7 *);
	int (*seq_show)(struct seq_file___7 *, void *);
	void * (*seq_start)(struct seq_file___7 *, loff_t *);
	void * (*seq_next)(struct seq_file___7 *, void *, loff_t *);
	void (*seq_stop)(struct seq_file___7 *, void *);
	ssize_t (*read)(struct kernfs_open_file___7 *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file___7 *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file___7 *, struct poll_table_struct___7 *);
	int (*mmap)(struct kernfs_open_file___7 *, struct vm_area_struct___7 *);
};

struct seq_file___7 {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations___7 *op;
	int poll_event;
	const struct file___7 *file;
	void *private;
};

struct kernfs_open_file___7 {
	struct kernfs_node___7 *kn;
	struct file___7 *file;
	struct seq_file___7 *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct___7 *vm_ops;
};

typedef void (*poll_queue_proc___7)(struct file___7 *, wait_queue_head_t *, struct poll_table_struct___7 *);

struct poll_table_struct___7 {
	poll_queue_proc___7 _qproc;
	__poll_t _key;
};

struct sock___7;

struct kobj_ns_type_operations___7 {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock___7 *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

struct sk_buff___7;

struct sk_buff_list___7 {
	struct sk_buff___7 *next;
	struct sk_buff___7 *prev;
};

struct sk_buff_head___7 {
	union {
		struct {
			struct sk_buff___7 *next;
			struct sk_buff___7 *prev;
		};
		struct sk_buff_list___7 list;
	};
	__u32 qlen;
	spinlock_t lock;
};

struct dst_entry___4;

struct socket___7;

struct net_device___7;

struct sock___7 {
	struct sock_common __sk_common;
	struct dst_entry___4 *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	socket_lock_t sk_lock;
	atomic_t sk_drops;
	int sk_rcvlowat;
	struct sk_buff_head___7 sk_error_queue;
	struct sk_buff_head___7 sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	int sk_forward_alloc;
	u32 sk_reserved_mem;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	int sk_rcvbuf;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	struct xfrm_policy *sk_policy[2];
	struct dst_entry___4 *sk_dst_cache;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head___7 sk_write_queue;
	__s32 sk_peek_off;
	int sk_write_pending;
	__u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	long int sk_sndtimeo;
	struct timer_list sk_timer;
	__u32 sk_priority;
	__u32 sk_mark;
	long unsigned int sk_pacing_rate;
	long unsigned int sk_max_pacing_rate;
	struct page_frag___7 sk_frag;
	netdev_features_t sk_route_caps;
	int sk_gso_type;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	__u32 sk_txhash;
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_userlocks: 4;
	u8 sk_pacing_shift;
	u16 sk_type;
	u16 sk_protocol;
	u16 sk_gso_max_segs;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	u8 sk_txrehash;
	u8 sk_prefer_busy_poll;
	u16 sk_busy_poll_budget;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid___3 *sk_peer_pid;
	const struct cred *sk_peer_cred;
	long int sk_rcvtimeo;
	ktime_t sk_stamp;
	u16 sk_tsflags;
	u8 sk_shutdown;
	atomic_t sk_tskey;
	atomic_t sk_zckey;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	struct socket___7 *sk_socket;
	void *sk_user_data;
	void *sk_security;
	struct sock_cgroup_data sk_cgrp_data;
	struct mem_cgroup___7 *sk_memcg;
	void (*sk_state_change)(struct sock___7 *);
	void (*sk_data_ready)(struct sock___7 *);
	void (*sk_write_space)(struct sock___7 *);
	void (*sk_error_report)(struct sock___7 *);
	int (*sk_backlog_rcv)(struct sock___7 *, struct sk_buff___7 *);
	struct sk_buff___7 * (*sk_validate_xmit_skb)(struct sock___7 *, struct net_device___7 *, struct sk_buff___7 *);
	void (*sk_destruct)(struct sock___7 *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
	struct hlist_node sk_bind2_node;
};

struct bin_attribute___7 {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space___7 * (*f_mapping)();
	ssize_t (*read)(struct file___7 *, struct kobject___7 *, struct bin_attribute___7 *, char *, loff_t, size_t);
	ssize_t (*write)(struct file___7 *, struct kobject___7 *, struct bin_attribute___7 *, char *, loff_t, size_t);
	int (*mmap)(struct file___7 *, struct kobject___7 *, struct bin_attribute___7 *, struct vm_area_struct___7 *);
};

struct sysfs_ops___7 {
	ssize_t (*show)(struct kobject___7 *, struct attribute *, char *);
	ssize_t (*store)(struct kobject___7 *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops___7;

struct kset___7 {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject___7 kobj;
	const struct kset_uevent_ops___7 *uevent_ops;
};

struct kobj_type___7 {
	void (*release)(struct kobject___7 *);
	const struct sysfs_ops___7 *sysfs_ops;
	const struct attribute_group___7 **default_groups;
	const struct kobj_ns_type_operations___7 * (*child_ns_type)(struct kobject___7 *);
	const void * (*namespace)(struct kobject___7 *);
	void (*get_ownership)(struct kobject___7 *, kuid_t *, kgid_t *);
};

struct kset_uevent_ops___7 {
	int (* const filter)(struct kobject___7 *);
	const char * (* const name)(struct kobject___7 *);
	int (* const uevent)(struct kobject___7 *, struct kobj_uevent_env *);
};

struct kparam_array___7;

struct kernel_param___7 {
	const char *name;
	struct module___7 *mod;
	const struct kernel_param_ops___7 *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array___7 *arr;
	};
};

struct kparam_array___7 {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops___7 *ops;
	void *elem;
};

struct module_attribute___7 {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute___7 *, struct module_kobject___7 *, char *);
	ssize_t (*store)(struct module_attribute___7 *, struct module_kobject___7 *, const char *, size_t);
	void (*setup)(struct module___7 *, const char *);
	int (*test)(struct module___7 *);
	void (*free)(struct module___7 *);
};

struct trace_event_call___2 {
	struct list_head list;
	struct trace_event_class *class;
	union {
		char *name;
		struct tracepoint *tp;
	};
	struct trace_event event;
	char *print_fmt;
	struct event_filter *filter;
	union {
		void *module;
		atomic_t refcnt;
	};
	void *data;
	int flags;
	int perf_refcount;
	struct hlist_head *perf_events;
	struct bpf_prog_array *prog_array;
	int (*perf_perm)(struct trace_event_call___2 *, struct perf_event___2 *);
};

struct wakeup_source___7;

struct dev_pm_info___7 {
	pm_message_t power_state;
	unsigned int can_wakeup: 1;
	unsigned int async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	struct list_head entry;
	struct completion completion;
	struct wakeup_source___7 *wakeup;
	bool wakeup_path: 1;
	bool syscore: 1;
	bool no_pm_callbacks: 1;
	unsigned int must_resume: 1;
	unsigned int may_skip_resume: 1;
	struct hrtimer suspend_timer;
	u64 timer_expires;
	struct work_struct work;
	wait_queue_head_t wait_queue;
	struct wake_irq *wakeirq;
	atomic_t usage_count;
	atomic_t child_count;
	unsigned int disable_depth: 3;
	unsigned int idle_notification: 1;
	unsigned int request_pending: 1;
	unsigned int deferred_resume: 1;
	unsigned int needs_force_resume: 1;
	unsigned int runtime_auto: 1;
	bool ignore_children: 1;
	unsigned int no_callbacks: 1;
	unsigned int irq_safe: 1;
	unsigned int use_autosuspend: 1;
	unsigned int timer_autosuspends: 1;
	unsigned int memalloc_noio: 1;
	unsigned int links_count;
	enum rpm_request request;
	enum rpm_status runtime_status;
	enum rpm_status last_status;
	int runtime_error;
	int autosuspend_delay;
	u64 last_busy;
	u64 active_time;
	u64 suspended_time;
	u64 accounting_timestamp;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device___7 *, s32);
	struct dev_pm_qos *qos;
};

struct device_type___7;

struct bus_type___7;

struct device_driver___7;

struct dev_pm_domain___7;

struct fwnode_handle___7;

struct class___7;

struct device___7 {
	struct kobject___7 kobj;
	struct device___7 *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type___7 *type;
	struct bus_type___7 *bus;
	struct device_driver___7 *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info___7 power;
	struct dev_pm_domain___7 *pm_domain;
	struct em_perf_domain *em_pd;
	struct dev_pin_info *pins;
	struct dev_msi_info msi;
	const struct dma_map_ops *dma_ops;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct cma *cma_area;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle___7 *fwnode;
	int numa_node;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	struct class___7 *class;
	const struct attribute_group___7 **groups;
	void (*release)(struct device___7 *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
};

struct dev_pm_ops___7 {
	int (*prepare)(struct device___7 *);
	void (*complete)(struct device___7 *);
	int (*suspend)(struct device___7 *);
	int (*resume)(struct device___7 *);
	int (*freeze)(struct device___7 *);
	int (*thaw)(struct device___7 *);
	int (*poweroff)(struct device___7 *);
	int (*restore)(struct device___7 *);
	int (*suspend_late)(struct device___7 *);
	int (*resume_early)(struct device___7 *);
	int (*freeze_late)(struct device___7 *);
	int (*thaw_early)(struct device___7 *);
	int (*poweroff_late)(struct device___7 *);
	int (*restore_early)(struct device___7 *);
	int (*suspend_noirq)(struct device___7 *);
	int (*resume_noirq)(struct device___7 *);
	int (*freeze_noirq)(struct device___7 *);
	int (*thaw_noirq)(struct device___7 *);
	int (*poweroff_noirq)(struct device___7 *);
	int (*restore_noirq)(struct device___7 *);
	int (*runtime_suspend)(struct device___7 *);
	int (*runtime_resume)(struct device___7 *);
	int (*runtime_idle)(struct device___7 *);
};

struct wakeup_source___7 {
	const char *name;
	int id;
	struct list_head entry;
	spinlock_t lock;
	struct wake_irq *wakeirq;
	struct timer_list timer;
	long unsigned int timer_expires;
	ktime_t total_time;
	ktime_t max_time;
	ktime_t last_time;
	ktime_t start_prevent_time;
	ktime_t prevent_sleep_time;
	long unsigned int event_count;
	long unsigned int active_count;
	long unsigned int relax_count;
	long unsigned int expire_count;
	long unsigned int wakeup_count;
	struct device___7 *dev;
	bool active: 1;
	bool autosleep_enabled: 1;
};

struct dev_pm_domain___7 {
	struct dev_pm_ops___7 ops;
	int (*start)(struct device___7 *);
	void (*detach)(struct device___7 *, bool);
	int (*activate)(struct device___7 *);
	void (*sync)(struct device___7 *);
	void (*dismiss)(struct device___7 *);
};

struct bus_type___7 {
	const char *name;
	const char *dev_name;
	struct device___7 *dev_root;
	const struct attribute_group___7 **bus_groups;
	const struct attribute_group___7 **dev_groups;
	const struct attribute_group___7 **drv_groups;
	int (*match)(struct device___7 *, struct device_driver___7 *);
	int (*uevent)(struct device___7 *, struct kobj_uevent_env *);
	int (*probe)(struct device___7 *);
	void (*sync_state)(struct device___7 *);
	void (*remove)(struct device___7 *);
	void (*shutdown)(struct device___7 *);
	int (*online)(struct device___7 *);
	int (*offline)(struct device___7 *);
	int (*suspend)(struct device___7 *, pm_message_t);
	int (*resume)(struct device___7 *);
	int (*num_vf)(struct device___7 *);
	int (*dma_configure)(struct device___7 *);
	void (*dma_cleanup)(struct device___7 *);
	const struct dev_pm_ops___7 *pm;
	const struct iommu_ops *iommu_ops;
	struct subsys_private *p;
	struct lock_class_key lock_key;
	bool need_parent_lock;
};

struct device_driver___7 {
	const char *name;
	struct bus_type___7 *bus;
	struct module___7 *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device___7 *);
	void (*sync_state)(struct device___7 *);
	int (*remove)(struct device___7 *);
	void (*shutdown)(struct device___7 *);
	int (*suspend)(struct device___7 *, pm_message_t);
	int (*resume)(struct device___7 *);
	const struct attribute_group___7 **groups;
	const struct attribute_group___7 **dev_groups;
	const struct dev_pm_ops___7 *pm;
	void (*coredump)(struct device___7 *);
	struct driver_private *p;
};

struct device_type___7 {
	const char *name;
	const struct attribute_group___7 **groups;
	int (*uevent)(struct device___7 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___7 *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device___7 *);
	const struct dev_pm_ops___7 *pm;
};

struct class___7 {
	const char *name;
	struct module___7 *owner;
	const struct attribute_group___7 **class_groups;
	const struct attribute_group___7 **dev_groups;
	struct kobject___7 *dev_kobj;
	int (*dev_uevent)(struct device___7 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___7 *, umode_t *);
	void (*class_release)(struct class___7 *);
	void (*dev_release)(struct device___7 *);
	int (*shutdown_pre)(struct device___7 *);
	const struct kobj_ns_type_operations___7 *ns_type;
	const void * (*namespace)(struct device___7 *);
	void (*get_ownership)(struct device___7 *, kuid_t *, kgid_t *);
	const struct dev_pm_ops___7 *pm;
	struct subsys_private *p;
};

struct fwnode_operations___7;

struct fwnode_handle___7 {
	struct fwnode_handle___7 *secondary;
	const struct fwnode_operations___7 *ops;
	struct device___7 *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

struct bio_vec___7 {
	struct page___7 *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct iov_iter___7 {
	u8 iter_type;
	bool nofault;
	bool data_source;
	bool user_backed;
	union {
		size_t iov_offset;
		int last_offset;
	};
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec___7 *bvec;
		struct xarray *xarray;
		struct pipe_inode_info___7 *pipe;
		void *ubuf;
	};
	union {
		long unsigned int nr_segs;
		struct {
			unsigned int head;
			unsigned int start_head;
		};
		loff_t xarray_start;
	};
};

struct ubuf_info___7;

struct msghdr___7 {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter___7 msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb___7 *msg_iocb;
	struct ubuf_info___7 *msg_ubuf;
	int (*sg_from_iter)(struct sock___7 *, struct sk_buff___7 *, struct iov_iter___7 *, size_t);
};

struct kiocb___7 {
	struct file___7 *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb___7 *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	struct wait_page_queue *ki_waitq;
};

struct ubuf_info___7 {
	void (*callback)(struct sk_buff___7 *, struct ubuf_info___7 *, bool);
	refcount_t refcnt;
	u8 flags;
};

struct sk_buff___7 {
	union {
		struct {
			struct sk_buff___7 *next;
			struct sk_buff___7 *prev;
			union {
				struct net_device___7 *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	union {
		struct sock___7 *sk;
		int ip_defrag_offset;
	};
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff___7 *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};

struct inet_frags___4;

struct fqdir___5 {
	long int high_thresh;
	long int low_thresh;
	int timeout;
	int max_dist;
	struct inet_frags___4 *f;
	struct net___7 *net;
	bool dead;
	long: 56;
	long: 64;
	long: 64;
	struct rhashtable rhashtable;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t mem;
	struct work_struct destroy_work;
	struct llist_node free_list;
	long: 64;
	long: 64;
};

struct inet_frag_queue___4;

struct inet_frags___4 {
	unsigned int qsize;
	void (*constructor)(struct inet_frag_queue___4 *, const void *);
	void (*destructor)(struct inet_frag_queue___4 *);
	void (*frag_expire)(struct timer_list *);
	struct kmem_cache *frags_cachep;
	const char *frags_cache_name;
	struct rhashtable_params rhash_params;
	refcount_t refcnt;
	struct completion completion;
};

struct fib_rules_ops___4;

struct fib_notifier_ops___4;

struct netns_ipv4___4 {
	struct inet_timewait_death_row tcp_death_row;
	struct ctl_table_header *forw_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *ipv4_hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *xfrm4_hdr;
	struct ipv4_devconf *devconf_all;
	struct ipv4_devconf *devconf_dflt;
	struct ip_ra_chain *ra_chain;
	struct mutex ra_mutex;
	struct fib_rules_ops___4 *rules_ops;
	struct fib_table *fib_main;
	struct fib_table *fib_default;
	unsigned int fib_rules_require_fldissect;
	bool fib_has_custom_rules;
	bool fib_has_custom_local_routes;
	bool fib_offload_disabled;
	atomic_t fib_num_tclassid_users;
	struct hlist_head *fib_table_hash;
	struct sock___7 *fibnl;
	struct sock___7 *mc_autojoin_sk;
	struct inet_peer_base *peers;
	struct fqdir___5 *fqdir;
	u8 sysctl_icmp_echo_ignore_all;
	u8 sysctl_icmp_echo_enable_probe;
	u8 sysctl_icmp_echo_ignore_broadcasts;
	u8 sysctl_icmp_ignore_bogus_error_responses;
	u8 sysctl_icmp_errors_use_inbound_ifaddr;
	int sysctl_icmp_ratelimit;
	int sysctl_icmp_ratemask;
	u32 ip_rt_min_pmtu;
	int ip_rt_mtu_expires;
	int ip_rt_min_advmss;
	struct local_ports ip_local_ports;
	u8 sysctl_tcp_ecn;
	u8 sysctl_tcp_ecn_fallback;
	u8 sysctl_ip_default_ttl;
	u8 sysctl_ip_no_pmtu_disc;
	u8 sysctl_ip_fwd_use_pmtu;
	u8 sysctl_ip_fwd_update_priority;
	u8 sysctl_ip_nonlocal_bind;
	u8 sysctl_ip_autobind_reuse;
	u8 sysctl_ip_dynaddr;
	u8 sysctl_ip_early_demux;
	u8 sysctl_raw_l3mdev_accept;
	u8 sysctl_tcp_early_demux;
	u8 sysctl_udp_early_demux;
	u8 sysctl_nexthop_compat_mode;
	u8 sysctl_fwmark_reflect;
	u8 sysctl_tcp_fwmark_accept;
	u8 sysctl_tcp_l3mdev_accept;
	u8 sysctl_tcp_mtu_probing;
	int sysctl_tcp_mtu_probe_floor;
	int sysctl_tcp_base_mss;
	int sysctl_tcp_min_snd_mss;
	int sysctl_tcp_probe_threshold;
	u32 sysctl_tcp_probe_interval;
	int sysctl_tcp_keepalive_time;
	int sysctl_tcp_keepalive_intvl;
	u8 sysctl_tcp_keepalive_probes;
	u8 sysctl_tcp_syn_retries;
	u8 sysctl_tcp_synack_retries;
	u8 sysctl_tcp_syncookies;
	u8 sysctl_tcp_migrate_req;
	u8 sysctl_tcp_comp_sack_nr;
	int sysctl_tcp_reordering;
	u8 sysctl_tcp_retries1;
	u8 sysctl_tcp_retries2;
	u8 sysctl_tcp_orphan_retries;
	u8 sysctl_tcp_tw_reuse;
	int sysctl_tcp_fin_timeout;
	unsigned int sysctl_tcp_notsent_lowat;
	u8 sysctl_tcp_sack;
	u8 sysctl_tcp_window_scaling;
	u8 sysctl_tcp_timestamps;
	u8 sysctl_tcp_early_retrans;
	u8 sysctl_tcp_recovery;
	u8 sysctl_tcp_thin_linear_timeouts;
	u8 sysctl_tcp_slow_start_after_idle;
	u8 sysctl_tcp_retrans_collapse;
	u8 sysctl_tcp_stdurg;
	u8 sysctl_tcp_rfc1337;
	u8 sysctl_tcp_abort_on_overflow;
	u8 sysctl_tcp_fack;
	int sysctl_tcp_max_reordering;
	int sysctl_tcp_adv_win_scale;
	u8 sysctl_tcp_dsack;
	u8 sysctl_tcp_app_win;
	u8 sysctl_tcp_frto;
	u8 sysctl_tcp_nometrics_save;
	u8 sysctl_tcp_no_ssthresh_metrics_save;
	u8 sysctl_tcp_moderate_rcvbuf;
	u8 sysctl_tcp_tso_win_divisor;
	u8 sysctl_tcp_workaround_signed_windows;
	int sysctl_tcp_limit_output_bytes;
	int sysctl_tcp_challenge_ack_limit;
	int sysctl_tcp_min_rtt_wlen;
	u8 sysctl_tcp_min_tso_segs;
	u8 sysctl_tcp_tso_rtt_log;
	u8 sysctl_tcp_autocorking;
	u8 sysctl_tcp_reflect_tos;
	int sysctl_tcp_invalid_ratelimit;
	int sysctl_tcp_pacing_ss_ratio;
	int sysctl_tcp_pacing_ca_ratio;
	int sysctl_tcp_wmem[3];
	int sysctl_tcp_rmem[3];
	unsigned int sysctl_tcp_child_ehash_entries;
	long unsigned int sysctl_tcp_comp_sack_delay_ns;
	long unsigned int sysctl_tcp_comp_sack_slack_ns;
	int sysctl_max_syn_backlog;
	int sysctl_tcp_fastopen;
	const struct tcp_congestion_ops *tcp_congestion_control;
	struct tcp_fastopen_context *tcp_fastopen_ctx;
	unsigned int sysctl_tcp_fastopen_blackhole_timeout;
	atomic_t tfo_active_disable_times;
	long unsigned int tfo_active_disable_stamp;
	u32 tcp_challenge_timestamp;
	u32 tcp_challenge_count;
	int sysctl_udp_wmem_min;
	int sysctl_udp_rmem_min;
	u8 sysctl_fib_notify_on_flag_change;
	u8 sysctl_udp_l3mdev_accept;
	u8 sysctl_igmp_llm_reports;
	int sysctl_igmp_max_memberships;
	int sysctl_igmp_max_msf;
	int sysctl_igmp_qrv;
	struct ping_group_range ping_group_range;
	atomic_t dev_addr_genid;
	long unsigned int *sysctl_local_reserved_ports;
	int sysctl_ip_prot_sock;
	struct list_head mr_tables;
	struct fib_rules_ops___4 *mr_rules_ops;
	u32 sysctl_fib_multipath_hash_fields;
	u8 sysctl_fib_multipath_use_neigh;
	u8 sysctl_fib_multipath_hash_policy;
	struct fib_notifier_ops___4 *notifier_ops;
	unsigned int fib_seq;
	struct fib_notifier_ops___4 *ipmr_notifier_ops;
	unsigned int ipmr_seq;
	atomic_t rt_genid;
	siphash_key_t ip_id_key;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct neighbour___4;

struct dst_ops___4 {
	short unsigned int family;
	unsigned int gc_thresh;
	int (*gc)(struct dst_ops___4 *);
	struct dst_entry___4 * (*check)(struct dst_entry___4 *, __u32);
	unsigned int (*default_advmss)(const struct dst_entry___4 *);
	unsigned int (*mtu)(const struct dst_entry___4 *);
	u32 * (*cow_metrics)(struct dst_entry___4 *, long unsigned int);
	void (*destroy)(struct dst_entry___4 *);
	void (*ifdown)(struct dst_entry___4 *, struct net_device___7 *, int);
	struct dst_entry___4 * (*negative_advice)(struct dst_entry___4 *);
	void (*link_failure)(struct sk_buff___7 *);
	void (*update_pmtu)(struct dst_entry___4 *, struct sock___7 *, struct sk_buff___7 *, u32, bool);
	void (*redirect)(struct dst_entry___4 *, struct sock___7 *, struct sk_buff___7 *);
	int (*local_out)(struct net___7 *, struct sock___7 *, struct sk_buff___7 *);
	struct neighbour___4 * (*neigh_lookup)(const struct dst_entry___4 *, struct sk_buff___7 *, const void *);
	void (*confirm_neigh)(const struct dst_entry___4 *, const void *);
	struct kmem_cache *kmem_cachep;
	struct percpu_counter pcpuc_entries;
	long: 64;
	long: 64;
	long: 64;
};

struct fib6_info___4;

struct rt6_info___4;

struct fib6_table___4;

struct netns_ipv6___4 {
	struct dst_ops___4 ip6_dst_ops;
	struct netns_sysctl_ipv6 sysctl;
	struct ipv6_devconf *devconf_all;
	struct ipv6_devconf *devconf_dflt;
	struct inet_peer_base *peers;
	struct fqdir___5 *fqdir;
	struct fib6_info___4 *fib6_null_entry;
	struct rt6_info___4 *ip6_null_entry;
	struct rt6_statistics *rt6_stats;
	struct timer_list ip6_fib_timer;
	struct hlist_head *fib_table_hash;
	struct fib6_table___4 *fib6_main_tbl;
	struct list_head fib6_walkers;
	rwlock_t fib6_walker_lock;
	spinlock_t fib6_gc_lock;
	atomic_t ip6_rt_gc_expire;
	long unsigned int ip6_rt_last_gc;
	unsigned char flowlabel_has_excl;
	bool fib6_has_custom_rules;
	unsigned int fib6_rules_require_fldissect;
	unsigned int fib6_routes_require_src;
	struct rt6_info___4 *ip6_prohibit_entry;
	struct rt6_info___4 *ip6_blk_hole_entry;
	struct fib6_table___4 *fib6_local_tbl;
	struct fib_rules_ops___4 *fib6_rules_ops;
	struct sock___7 *ndisc_sk;
	struct sock___7 *tcp_sk;
	struct sock___7 *igmp_sk;
	struct sock___7 *mc_autojoin_sk;
	struct hlist_head *inet6_addr_lst;
	spinlock_t addrconf_hash_lock;
	struct delayed_work addr_chk_work;
	struct list_head mr6_tables;
	struct fib_rules_ops___4 *mr6_rules_ops;
	atomic_t dev_addr_genid;
	atomic_t fib6_sernum;
	struct seg6_pernet_data *seg6_data;
	struct fib_notifier_ops___4 *notifier_ops;
	struct fib_notifier_ops___4 *ip6mr_notifier_ops;
	unsigned int ipmr_seq;
	struct {
		struct hlist_head head;
		spinlock_t lock;
		u32 seq;
	} ip6addrlbl_table;
	struct ioam6_pernet_data *ioam6_data;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct netns_ieee802154_lowpan___4 {
	struct netns_sysctl_lowpan sysctl;
	struct fqdir___5 *fqdir;
};

struct netns_sctp___4 {
	struct sctp_mib *sctp_statistics;
	struct proc_dir_entry *proc_net_sctp;
	struct ctl_table_header *sysctl_header;
	struct sock___7 *ctl_sock;
	struct sock___7 *udp4_sock;
	struct sock___7 *udp6_sock;
	int udp_port;
	int encap_port;
	struct list_head local_addr_list;
	struct list_head addr_waitq;
	struct timer_list addr_wq_timer;
	struct list_head auto_asconf_splist;
	spinlock_t addr_wq_lock;
	spinlock_t local_addr_lock;
	unsigned int rto_initial;
	unsigned int rto_min;
	unsigned int rto_max;
	int rto_alpha;
	int rto_beta;
	int max_burst;
	int cookie_preserve_enable;
	char *sctp_hmac_alg;
	unsigned int valid_cookie_life;
	unsigned int sack_timeout;
	unsigned int hb_interval;
	unsigned int probe_interval;
	int max_retrans_association;
	int max_retrans_path;
	int max_retrans_init;
	int pf_retrans;
	int ps_retrans;
	int pf_enable;
	int pf_expose;
	int sndbuf_policy;
	int rcvbuf_policy;
	int default_auto_asconf;
	int addip_enable;
	int addip_noauth;
	int prsctp_enable;
	int reconf_enable;
	int auth_enable;
	int intl_enable;
	int ecn_enable;
	int scope_policy;
	int rwnd_upd_shift;
	long unsigned int max_autoclose;
};

struct netns_xfrm___4 {
	struct list_head state_all;
	struct hlist_head *state_bydst;
	struct hlist_head *state_bysrc;
	struct hlist_head *state_byspi;
	struct hlist_head *state_byseq;
	unsigned int state_hmask;
	unsigned int state_num;
	struct work_struct state_hash_work;
	struct list_head policy_all;
	struct hlist_head *policy_byidx;
	unsigned int policy_idx_hmask;
	struct hlist_head policy_inexact[3];
	struct xfrm_policy_hash policy_bydst[3];
	unsigned int policy_count[6];
	struct work_struct policy_hash_work;
	struct xfrm_policy_hthresh policy_hthresh;
	struct list_head inexact_bins;
	struct sock___7 *nlsk;
	struct sock___7 *nlsk_stash;
	u32 sysctl_aevent_etime;
	u32 sysctl_aevent_rseqth;
	int sysctl_larval_drop;
	u32 sysctl_acq_expires;
	u8 policy_default[3];
	struct ctl_table_header *sysctl_hdr;
	long: 64;
	long: 64;
	long: 64;
	struct dst_ops___4 xfrm4_dst_ops;
	struct dst_ops___4 xfrm6_dst_ops;
	spinlock_t xfrm_state_lock;
	seqcount_spinlock_t xfrm_state_hash_generation;
	seqcount_spinlock_t xfrm_policy_hash_generation;
	spinlock_t xfrm_policy_lock;
	struct mutex xfrm_cfg_mutex;
	long: 64;
	long: 64;
};

struct net___7 {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	atomic_t dev_unreg_count;
	unsigned int dev_base_seq;
	int ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node cleanup_list;
	struct key_tag *key_domain;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
	struct sock___7 *rtnl;
	struct sock___7 *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device___7 *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_ipv4___4 ipv4;
	struct netns_ipv6___4 ipv6;
	struct netns_ieee802154_lowpan___4 ieee802154_lowpan;
	struct netns_sctp___4 sctp;
	struct netns_nf___2 nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct netns_ft ft;
	struct sk_buff_head___7 wext_nlevents;
	struct net_generic *gen;
	struct netns_bpf bpf;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_xfrm___4 xfrm;
	u64 net_cookie;
	struct netns_ipvs *ipvs;
	struct netns_mpls mpls;
	struct netns_can can;
	struct netns_xdp xdp;
	struct netns_mctp mctp;
	struct sock___7 *crypto_nlsk;
	struct sock___7 *diag_nlsk;
	struct netns_smc smc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct inet_frag_queue___4 {
	struct rhash_head node;
	union {
		struct frag_v4_compare_key v4;
		struct frag_v6_compare_key v6;
	} key;
	struct timer_list timer;
	spinlock_t lock;
	refcount_t refcnt;
	struct rb_root rb_fragments;
	struct sk_buff___7 *fragments_tail;
	struct sk_buff___7 *last_run_head;
	ktime_t stamp;
	int len;
	int meat;
	u8 mono_delivery_time;
	__u8 flags;
	u16 max_size;
	struct fqdir___5 *fqdir;
	struct callback_head rcu;
};

struct fib_rules_ops___4 {
	int family;
	struct list_head list;
	int rule_size;
	int addr_size;
	int unresolved_rules;
	int nr_goto_rules;
	unsigned int fib_rules_seq;
	int (*action)(struct fib_rule *, struct flowi *, int, struct fib_lookup_arg *);
	bool (*suppress)(struct fib_rule *, int, struct fib_lookup_arg *);
	int (*match)(struct fib_rule *, struct flowi *, int);
	int (*configure)(struct fib_rule *, struct sk_buff___7 *, struct fib_rule_hdr *, struct nlattr **, struct netlink_ext_ack *);
	int (*delete)(struct fib_rule *);
	int (*compare)(struct fib_rule *, struct fib_rule_hdr *, struct nlattr **);
	int (*fill)(struct fib_rule *, struct sk_buff___7 *, struct fib_rule_hdr *);
	size_t (*nlmsg_payload)(struct fib_rule *);
	void (*flush_cache)(struct fib_rules_ops___4 *);
	int nlgroup;
	struct list_head rules_list;
	struct module___7 *owner;
	struct net___7 *fro_net;
	struct callback_head rcu;
};

struct fib_notifier_ops___4 {
	int family;
	struct list_head list;
	unsigned int (*fib_seq_read)(struct net___7 *);
	int (*fib_dump)(struct net___7 *, struct notifier_block *, struct netlink_ext_ack *);
	struct module___7 *owner;
	struct callback_head rcu;
};

struct dst_entry___4 {
	struct net_device___7 *dev;
	struct dst_ops___4 *ops;
	long unsigned int _metrics;
	long unsigned int expires;
	struct xfrm_state *xfrm;
	int (*input)(struct sk_buff___7 *);
	int (*output)(struct net___7 *, struct sock___7 *, struct sk_buff___7 *);
	short unsigned int flags;
	short int obsolete;
	short unsigned int header_len;
	short unsigned int trailer_len;
	atomic_t __refcnt;
	int __use;
	long unsigned int lastuse;
	struct lwtunnel_state *lwtstate;
	struct callback_head callback_head;
	short int error;
	short int __pad;
	__u32 tclassid;
	netdevice_tracker dev_tracker;
};

typedef rx_handler_result_t rx_handler_func_t___7(struct sk_buff___7 **);

struct net_device___7 {
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
	long unsigned int state;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct list_head ptype_specific;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	unsigned int flags;
	long long unsigned int priv_flags;
	const struct net_device_ops *netdev_ops;
	int ifindex;
	short unsigned int gflags;
	short unsigned int hard_header_len;
	unsigned int mtu;
	short unsigned int needed_headroom;
	short unsigned int needed_tailroom;
	netdev_features_t features;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	netdev_features_t gso_partial_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct iw_handler_def *wireless_handlers;
	struct iw_public_data *wireless_data;
	const struct ethtool_ops *ethtool_ops;
	const struct l3mdev_ops *l3mdev_ops;
	const struct ndisc_ops *ndisc_ops;
	const struct xfrmdev_ops *xfrmdev_ops;
	const struct tlsdev_ops *tlsdev_ops;
	const struct header_ops *header_ops;
	unsigned char operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	short unsigned int padded;
	spinlock_t addr_list_lock;
	int irq;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset___7 *queues_kset;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct inet6_dev *ip6_ptr;
	struct vlan_info *vlan_info;
	struct dsa_port *dsa_ptr;
	struct tipc_bearer *tipc_ptr;
	void *atalk_ptr;
	void *ax25_ptr;
	struct wireless_dev *ieee80211_ptr;
	struct wpan_dev *ieee802154_ptr;
	struct mpls_dev *mpls_ptr;
	struct mctp_dev *mctp_ptr;
	const unsigned char *dev_addr;
	struct netdev_rx_queue *_rx;
	unsigned int num_rx_queues;
	unsigned int real_num_rx_queues;
	struct bpf_prog *xdp_prog;
	long unsigned int gro_flush_timeout;
	int napi_defer_hard_irqs;
	unsigned int gro_max_size;
	rx_handler_func_t___7 *rx_handler;
	void *rx_handler_data;
	struct mini_Qdisc *miniq_ingress;
	struct netdev_queue *ingress_queue;
	struct nf_hook_entries *nf_hooks_ingress;
	unsigned char broadcast[32];
	struct cpu_rmap *rx_cpu_rmap;
	struct hlist_node index_hlist;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netdev_queue *_tx;
	unsigned int num_tx_queues;
	unsigned int real_num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct xps_dev_maps *xps_maps[2];
	struct mini_Qdisc *miniq_egress;
	struct nf_hook_entries *nf_hooks_egress;
	struct hlist_head qdisc_hash[16];
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	int *pcpu_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	enum {
		NETREG_UNINITIALIZED___7 = 0,
		NETREG_REGISTERED___7 = 1,
		NETREG_UNREGISTERING___7 = 2,
		NETREG_UNREGISTERED___7 = 3,
		NETREG_RELEASED___7 = 4,
		NETREG_DUMMY___7 = 5,
	} reg_state: 8;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED___7 = 0,
		RTNL_LINK_INITIALIZING___7 = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device___7 *);
	struct netpoll_info *npinfo;
	possible_net_t nd_net;
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	struct garp_port *garp_port;
	struct mrp_port *mrp_port;
	struct dm_hw_stat_delta *dm_private;
	struct device___7 dev;
	const struct attribute_group___7 *sysfs_groups[4];
	const struct attribute_group___7 *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	unsigned int gso_max_size;
	unsigned int tso_max_size;
	u16 gso_max_segs;
	u16 tso_max_segs;
	const struct dcbnl_rtnl_ops *dcbnl_ops;
	s16 num_tc;
	struct netdev_tc_txq tc_to_txq[16];
	u8 prio_tc_map[16];
	unsigned int fcoe_ddp_xid;
	struct netprio_map *priomap;
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	unsigned int wol_enabled: 1;
	unsigned int threaded: 1;
	struct list_head net_notifier_list;
	const struct macsec_ops *macsec_ops;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	long: 64;
	long: 64;
	long: 64;
};

struct neighbour___4 {
	struct neighbour___4 *next;
	struct neigh_table *tbl;
	struct neigh_parms *parms;
	long unsigned int confirmed;
	long unsigned int updated;
	rwlock_t lock;
	refcount_t refcnt;
	unsigned int arp_queue_len_bytes;
	struct sk_buff_head___7 arp_queue;
	struct timer_list timer;
	long unsigned int used;
	atomic_t probes;
	u8 nud_state;
	u8 type;
	u8 dead;
	u8 protocol;
	u32 flags;
	seqlock_t ha_lock;
	int: 32;
	unsigned char ha[32];
	struct hh_cache hh;
	int (*output)(struct neighbour___4 *, struct sk_buff___7 *);
	const struct neigh_ops *ops;
	struct list_head gc_list;
	struct list_head managed_list;
	struct callback_head rcu;
	struct net_device___7 *dev;
	netdevice_tracker dev_tracker;
	u8 primary_key[0];
};

struct fib6_info___4 {
	struct fib6_table___4 *fib6_table;
	struct fib6_info___4 *fib6_next;
	struct fib6_node *fib6_node;
	union {
		struct list_head fib6_siblings;
		struct list_head nh_list;
	};
	unsigned int fib6_nsiblings;
	refcount_t fib6_ref;
	long unsigned int expires;
	struct dst_metrics *fib6_metrics;
	struct rt6key fib6_dst;
	u32 fib6_flags;
	struct rt6key fib6_src;
	struct rt6key fib6_prefsrc;
	u32 fib6_metric;
	u8 fib6_protocol;
	u8 fib6_type;
	u8 offload;
	u8 trap;
	u8 offload_failed;
	u8 should_flush: 1;
	u8 dst_nocount: 1;
	u8 dst_nopolicy: 1;
	u8 fib6_destroying: 1;
	u8 unused: 4;
	struct callback_head rcu;
	struct nexthop *nh;
	struct fib6_nh fib6_nh[0];
};

struct rt6_info___4 {
	struct dst_entry___4 dst;
	struct fib6_info___4 *from;
	int sernum;
	struct rt6key rt6i_dst;
	struct rt6key rt6i_src;
	struct in6_addr rt6i_gateway;
	struct inet6_dev *rt6i_idev;
	u32 rt6i_flags;
	struct list_head rt6i_uncached;
	struct uncached_list *rt6i_uncached_list;
	short unsigned int rt6i_nfheader_len;
};

struct fib6_table___4 {
	struct hlist_node tb6_hlist;
	u32 tb6_id;
	spinlock_t tb6_lock;
	struct fib6_node tb6_root;
	struct inet_peer_base tb6_peers;
	unsigned int flags;
	unsigned int fib_seq;
};

struct dentry_operations___7;

struct dentry___7 {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry___7 *d_parent;
	struct qstr d_name;
	struct inode___7 *d_inode;
	unsigned char d_iname[32];
	struct lockref d_lockref;
	const struct dentry_operations___7 *d_op;
	struct super_block___7 *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct list_head d_child;
	struct list_head d_subdirs;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

struct inode_operations___7;

struct inode___7 {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations___7 *i_op;
	struct super_block___7 *i_sb;
	struct address_space___7 *i_mapping;
	void *i_security;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback___7 *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations___7 *i_fop;
		void (*free_inode)(struct inode___7 *);
	};
	struct file_lock_context *i_flctx;
	struct address_space___7 i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info___7 *i_pipe;
		struct cdev___2 *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_info *i_crypt_info;
	struct fsverity_info *i_verity_info;
	void *i_private;
};

struct dentry_operations___7 {
	int (*d_revalidate)(struct dentry___7 *, unsigned int);
	int (*d_weak_revalidate)(struct dentry___7 *, unsigned int);
	int (*d_hash)(const struct dentry___7 *, struct qstr *);
	int (*d_compare)(const struct dentry___7 *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry___7 *);
	int (*d_init)(struct dentry___7 *);
	void (*d_release)(struct dentry___7 *);
	void (*d_prune)(struct dentry___7 *);
	void (*d_iput)(struct dentry___7 *, struct inode___7 *);
	char * (*d_dname)(struct dentry___7 *, char *, int);
	struct vfsmount___7 * (*d_automount)(struct path___7 *);
	int (*d_manage)(const struct path___7 *, bool);
	struct dentry___7 * (*d_real)(struct dentry___7 *, const struct inode___7 *);
	long: 64;
	long: 64;
	long: 64;
};

struct quota_format_type___7;

struct mem_dqinfo___7 {
	struct quota_format_type___7 *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};

struct quota_format_ops___7;

struct quota_info___7 {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode___7 *files[3];
	struct mem_dqinfo___7 info[3];
	const struct quota_format_ops___7 *ops[3];
};

struct rcuwait___7 {
	struct task_struct___7 *task;
};

struct percpu_rw_semaphore___7 {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait___7 writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers___7 {
	int frozen;
	wait_queue_head_t wait_unfrozen;
	struct percpu_rw_semaphore___7 rw_sem[3];
};

struct shrink_control___7;

struct shrinker___7 {
	long unsigned int (*count_objects)(struct shrinker___7 *, struct shrink_control___7 *);
	long unsigned int (*scan_objects)(struct shrinker___7 *, struct shrink_control___7 *);
	long int batch;
	int seeks;
	unsigned int flags;
	struct list_head list;
	int id;
	atomic_long_t *nr_deferred;
};

struct super_operations___7;

struct dquot_operations___7;

struct quotactl_ops___7;

struct block_device___7;

struct super_block___7 {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type___7 *s_type;
	const struct super_operations___7 *s_op;
	const struct dquot_operations___7 *dq_op;
	const struct quotactl_ops___7 *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry___7 *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	void *s_security;
	const struct xattr_handler **s_xattr;
	const struct fscrypt_operations *s_cop;
	struct fscrypt_keyring *s_master_keys;
	const struct fsverity_operations *s_vop;
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device___7 *s_bdev;
	struct backing_dev_info___7 *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info___7 s_dquot;
	struct sb_writers___7 s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	__u32 s_fsnotify_mask;
	struct fsnotify_mark_connector *s_fsnotify_marks;
	char s_id[32];
	uuid_t s_uuid;
	unsigned int s_max_links;
	fmode_t s_mode;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations___7 *s_d_op;
	struct shrinker___7 s_shrink;
	atomic_long_t s_remove_count;
	atomic_long_t s_fsnotify_connectors;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 64;
	long: 64;
};

struct vfsmount___7 {
	struct dentry___7 *mnt_root;
	struct super_block___7 *mnt_sb;
	int mnt_flags;
	struct user_namespace *mnt_userns;
};

struct shrink_control___7 {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup___7 *memcg;
};

struct cgroup___7 {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	struct kernfs_node___7 *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	struct cgroup_file psi_files[4];
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[13];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[13];
	struct cgroup___7 *dom_cgrp;
	struct cgroup___7 *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group *psi;
	struct cgroup_bpf bpf;
	atomic_t congestion_count;
	struct cgroup_freezer_state freezer;
	struct cgroup___7 *ancestors[0];
};

struct core_thread___7 {
	struct task_struct___7 *task;
	struct core_thread___7 *next;
};

struct core_state___7 {
	atomic_t nr_threads;
	struct core_thread___7 dumper;
	struct completion startup;
};

struct iattr___7 {
	unsigned int ia_valid;
	umode_t ia_mode;
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file___7 *ia_file;
};

struct dquot___7 {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block___7 *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};

struct quota_format_type___7 {
	int qf_fmt_id;
	const struct quota_format_ops___7 *qf_ops;
	struct module___7 *qf_owner;
	struct quota_format_type___7 *qf_next;
};

struct quota_format_ops___7 {
	int (*check_quota_file)(struct super_block___7 *, int);
	int (*read_file_info)(struct super_block___7 *, int);
	int (*write_file_info)(struct super_block___7 *, int);
	int (*free_file_info)(struct super_block___7 *, int);
	int (*read_dqblk)(struct dquot___7 *);
	int (*commit_dqblk)(struct dquot___7 *);
	int (*release_dqblk)(struct dquot___7 *);
	int (*get_next_id)(struct super_block___7 *, struct kqid *);
};

struct dquot_operations___7 {
	int (*write_dquot)(struct dquot___7 *);
	struct dquot___7 * (*alloc_dquot)(struct super_block___7 *, int);
	void (*destroy_dquot)(struct dquot___7 *);
	int (*acquire_dquot)(struct dquot___7 *);
	int (*release_dquot)(struct dquot___7 *);
	int (*mark_dirty)(struct dquot___7 *);
	int (*write_info)(struct super_block___7 *, int);
	qsize_t * (*get_reserved_space)(struct inode___7 *);
	int (*get_projid)(struct inode___7 *, kprojid_t *);
	int (*get_inode_usage)(struct inode___7 *, qsize_t *);
	int (*get_next_id)(struct super_block___7 *, struct kqid *);
};

struct quotactl_ops___7 {
	int (*quota_on)(struct super_block___7 *, int, int, const struct path___7 *);
	int (*quota_off)(struct super_block___7 *, int);
	int (*quota_enable)(struct super_block___7 *, unsigned int);
	int (*quota_disable)(struct super_block___7 *, unsigned int);
	int (*quota_sync)(struct super_block___7 *, int);
	int (*set_info)(struct super_block___7 *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block___7 *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block___7 *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block___7 *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block___7 *, struct qc_state *);
	int (*rm_xquota)(struct super_block___7 *, unsigned int);
};

struct writeback_control___7;

struct address_space_operations___7 {
	int (*writepage)(struct page___7 *, struct writeback_control___7 *);
	int (*read_folio)(struct file___7 *, struct folio___7 *);
	int (*writepages)(struct address_space___7 *, struct writeback_control___7 *);
	bool (*dirty_folio)(struct address_space___7 *, struct folio___7 *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file___7 *, struct address_space___7 *, loff_t, unsigned int, struct page___7 **, void **);
	int (*write_end)(struct file___7 *, struct address_space___7 *, loff_t, unsigned int, unsigned int, struct page___7 *, void *);
	sector_t (*bmap)(struct address_space___7 *, sector_t);
	void (*invalidate_folio)(struct folio___7 *, size_t, size_t);
	bool (*release_folio)(struct folio___7 *, gfp_t);
	void (*free_folio)(struct folio___7 *);
	ssize_t (*direct_IO)(struct kiocb___7 *, struct iov_iter___7 *);
	int (*migrate_folio)(struct address_space___7 *, struct folio___7 *, struct folio___7 *, enum migrate_mode);
	int (*launder_folio)(struct folio___7 *);
	bool (*is_partially_uptodate)(struct folio___7 *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio___7 *, bool *, bool *);
	int (*error_remove_page)(struct address_space___7 *, struct page___7 *);
	int (*swap_activate)(struct swap_info_struct *, struct file___7 *, sector_t *);
	void (*swap_deactivate)(struct file___7 *);
	int (*swap_rw)(struct kiocb___7 *, struct iov_iter___7 *);
};

struct writeback_control___7 {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_fscache_wb: 1;
	unsigned int no_cgroup_owner: 1;
	unsigned int punt_to_cgroup: 1;
	struct swap_iocb **swap_plug;
	struct bdi_writeback___7 *wb;
	struct inode___7 *inode;
	int wb_id;
	int wb_lcand_id;
	int wb_tcand_id;
	size_t wb_bytes;
	size_t wb_lcand_bytes;
	size_t wb_tcand_bytes;
};

struct inode_operations___7 {
	struct dentry___7 * (*lookup)(struct inode___7 *, struct dentry___7 *, unsigned int);
	const char * (*get_link)(struct dentry___7 *, struct inode___7 *, struct delayed_call *);
	int (*permission)(struct user_namespace *, struct inode___7 *, int);
	struct posix_acl * (*get_acl)(struct inode___7 *, int, bool);
	int (*readlink)(struct dentry___7 *, char *, int);
	int (*create)(struct user_namespace *, struct inode___7 *, struct dentry___7 *, umode_t, bool);
	int (*link)(struct dentry___7 *, struct inode___7 *, struct dentry___7 *);
	int (*unlink)(struct inode___7 *, struct dentry___7 *);
	int (*symlink)(struct user_namespace *, struct inode___7 *, struct dentry___7 *, const char *);
	int (*mkdir)(struct user_namespace *, struct inode___7 *, struct dentry___7 *, umode_t);
	int (*rmdir)(struct inode___7 *, struct dentry___7 *);
	int (*mknod)(struct user_namespace *, struct inode___7 *, struct dentry___7 *, umode_t, dev_t);
	int (*rename)(struct user_namespace *, struct inode___7 *, struct dentry___7 *, struct inode___7 *, struct dentry___7 *, unsigned int);
	int (*setattr)(struct user_namespace *, struct dentry___7 *, struct iattr___7 *);
	int (*getattr)(struct user_namespace *, const struct path___7 *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry___7 *, char *, size_t);
	int (*fiemap)(struct inode___7 *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode___7 *, struct timespec64 *, int);
	int (*atomic_open)(struct inode___7 *, struct dentry___7 *, struct file___7 *, unsigned int, umode_t);
	int (*tmpfile)(struct user_namespace *, struct inode___7 *, struct file___7 *, umode_t);
	int (*set_acl)(struct user_namespace *, struct inode___7 *, struct posix_acl *, int);
	int (*fileattr_set)(struct user_namespace *, struct dentry___7 *, struct fileattr *);
	int (*fileattr_get)(struct dentry___7 *, struct fileattr *);
	long: 64;
};

struct file_lock_operations___7 {
	void (*fl_copy_lock)(struct file_lock___7 *, struct file_lock___7 *);
	void (*fl_release_private)(struct file_lock___7 *);
};

struct lock_manager_operations___7;

struct file_lock___7 {
	struct file_lock___7 *fl_blocker;
	struct list_head fl_list;
	struct hlist_node fl_link;
	struct list_head fl_blocked_requests;
	struct list_head fl_blocked_member;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	unsigned int fl_pid;
	int fl_link_cpu;
	wait_queue_head_t fl_wait;
	struct file___7 *fl_file;
	loff_t fl_start;
	loff_t fl_end;
	struct fasync_struct___7 *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct file_lock_operations___7 *fl_ops;
	const struct lock_manager_operations___7 *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
	} fl_u;
};

struct lock_manager_operations___7 {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock___7 *);
	int (*lm_grant)(struct file_lock___7 *, int);
	bool (*lm_break)(struct file_lock___7 *);
	int (*lm_change)(struct file_lock___7 *, int, struct list_head *);
	void (*lm_setup)(struct file_lock___7 *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lock___7 *);
	bool (*lm_lock_expirable)(struct file_lock___7 *);
	void (*lm_expire_lock)();
};

struct fasync_struct___7 {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct___7 *fa_next;
	struct file___7 *fa_file;
	struct callback_head fa_rcu;
};

struct super_operations___7 {
	struct inode___7 * (*alloc_inode)(struct super_block___7 *);
	void (*destroy_inode)(struct inode___7 *);
	void (*free_inode)(struct inode___7 *);
	void (*dirty_inode)(struct inode___7 *, int);
	int (*write_inode)(struct inode___7 *, struct writeback_control___7 *);
	int (*drop_inode)(struct inode___7 *);
	void (*evict_inode)(struct inode___7 *);
	void (*put_super)(struct super_block___7 *);
	int (*sync_fs)(struct super_block___7 *, int);
	int (*freeze_super)(struct super_block___7 *);
	int (*freeze_fs)(struct super_block___7 *);
	int (*thaw_super)(struct super_block___7 *);
	int (*unfreeze_fs)(struct super_block___7 *);
	int (*statfs)(struct dentry___7 *, struct kstatfs *);
	int (*remount_fs)(struct super_block___7 *, int *, char *);
	void (*umount_begin)(struct super_block___7 *);
	int (*show_options)(struct seq_file___7 *, struct dentry___7 *);
	int (*show_devname)(struct seq_file___7 *, struct dentry___7 *);
	int (*show_path)(struct seq_file___7 *, struct dentry___7 *);
	int (*show_stats)(struct seq_file___7 *, struct dentry___7 *);
	ssize_t (*quota_read)(struct super_block___7 *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block___7 *, int, const char *, size_t, loff_t);
	struct dquot___7 ** (*get_dquots)(struct inode___7 *);
	long int (*nr_cached_objects)(struct super_block___7 *, struct shrink_control___7 *);
	long int (*free_cached_objects)(struct super_block___7 *, struct shrink_control___7 *);
};

struct block_device___7 {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	bool bd_read_only;
	dev_t bd_dev;
	atomic_t bd_openers;
	struct inode___7 *bd_inode;
	struct super_block___7 *bd_super;
	void *bd_claiming;
	struct device___7 bd_device;
	void *bd_holder;
	int bd_holders;
	bool bd_write_holder;
	struct kobject___7 *bd_holder_dir;
	u8 bd_partno;
	spinlock_t bd_size_lock;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	int bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct super_block___7 *bd_fsfreeze_sb;
	struct partition_meta_info *bd_meta_info;
};

typedef void bio_end_io_t___7(struct bio___7 *);

struct bio___7 {
	struct bio___7 *bi_next;
	struct block_device___7 *bi_bdev;
	blk_opf_t bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t___7 *bi_end_io;
	void *bi_private;
	struct blkcg_gq *bi_blkg;
	struct bio_issue bi_issue;
	u64 bi_iocost_cost;
	struct bio_crypt_ctx *bi_crypt_context;
	union {
		struct bio_integrity_payload *bi_integrity;
	};
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec___7 *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec___7 bi_inline_vecs[0];
};

struct dev_pagemap_ops___7 {
	void (*page_free)(struct page___7 *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault___7 *);
	int (*memory_failure)(struct dev_pagemap___7 *, long unsigned int, long unsigned int, int);
};

struct socket_wq___7 {
	wait_queue_head_t wait;
	struct fasync_struct___7 *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
	long: 64;
};

struct proto_ops___7;

struct socket___7 {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file___7 *file;
	struct sock___7 *sk;
	const struct proto_ops___7 *ops;
	long: 64;
	long: 64;
	long: 64;
	struct socket_wq___7 wq;
};

typedef int (*sk_read_actor_t___7)(read_descriptor_t *, struct sk_buff___7 *, unsigned int, size_t);

typedef int (*skb_read_actor_t___7)(struct sock___7 *, struct sk_buff___7 *);

struct proto_ops___7 {
	int family;
	struct module___7 *owner;
	int (*release)(struct socket___7 *);
	int (*bind)(struct socket___7 *, struct sockaddr *, int);
	int (*connect)(struct socket___7 *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket___7 *, struct socket___7 *);
	int (*accept)(struct socket___7 *, struct socket___7 *, int, bool);
	int (*getname)(struct socket___7 *, struct sockaddr *, int);
	__poll_t (*poll)(struct file___7 *, struct socket___7 *, struct poll_table_struct___7 *);
	int (*ioctl)(struct socket___7 *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct socket___7 *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket___7 *, void *, bool, bool);
	int (*listen)(struct socket___7 *, int);
	int (*shutdown)(struct socket___7 *, int);
	int (*setsockopt)(struct socket___7 *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket___7 *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file___7 *, struct socket___7 *);
	int (*sendmsg)(struct socket___7 *, struct msghdr___7 *, size_t);
	int (*recvmsg)(struct socket___7 *, struct msghdr___7 *, size_t, int);
	int (*mmap)(struct file___7 *, struct socket___7 *, struct vm_area_struct___7 *);
	ssize_t (*sendpage)(struct socket___7 *, struct page___7 *, int, size_t, int);
	ssize_t (*splice_read)(struct socket___7 *, loff_t *, struct pipe_inode_info___7 *, size_t, unsigned int);
	int (*set_peek_off)(struct sock___7 *, int);
	int (*peek_len)(struct socket___7 *);
	int (*read_sock)(struct sock___7 *, read_descriptor_t *, sk_read_actor_t___7);
	int (*read_skb)(struct sock___7 *, skb_read_actor_t___7);
	int (*sendpage_locked)(struct sock___7 *, struct page___7 *, int, size_t, int);
	int (*sendmsg_locked)(struct sock___7 *, struct msghdr___7 *, size_t);
	int (*set_rcvlowat)(struct sock___7 *, int);
};

struct fwnode_reference_args___7;

struct fwnode_endpoint___7;

struct fwnode_operations___7 {
	struct fwnode_handle___7 * (*get)(struct fwnode_handle___7 *);
	void (*put)(struct fwnode_handle___7 *);
	bool (*device_is_available)(const struct fwnode_handle___7 *);
	const void * (*device_get_match_data)(const struct fwnode_handle___7 *, const struct device___7 *);
	bool (*device_dma_supported)(const struct fwnode_handle___7 *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle___7 *);
	bool (*property_present)(const struct fwnode_handle___7 *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle___7 *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle___7 *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle___7 *);
	const char * (*get_name_prefix)(const struct fwnode_handle___7 *);
	struct fwnode_handle___7 * (*get_parent)(const struct fwnode_handle___7 *);
	struct fwnode_handle___7 * (*get_next_child_node)(const struct fwnode_handle___7 *, struct fwnode_handle___7 *);
	struct fwnode_handle___7 * (*get_named_child_node)(const struct fwnode_handle___7 *, const char *);
	int (*get_reference_args)(const struct fwnode_handle___7 *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args___7 *);
	struct fwnode_handle___7 * (*graph_get_next_endpoint)(const struct fwnode_handle___7 *, struct fwnode_handle___7 *);
	struct fwnode_handle___7 * (*graph_get_remote_endpoint)(const struct fwnode_handle___7 *);
	struct fwnode_handle___7 * (*graph_get_port_parent)(struct fwnode_handle___7 *);
	int (*graph_parse_endpoint)(const struct fwnode_handle___7 *, struct fwnode_endpoint___7 *);
	void * (*iomap)(struct fwnode_handle___7 *, int);
	int (*irq_get)(const struct fwnode_handle___7 *, unsigned int);
	int (*add_links)(struct fwnode_handle___7 *);
};

struct fwnode_endpoint___7 {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle___7 *local_fwnode;
};

struct fwnode_reference_args___7 {
	struct fwnode_handle___7 *fwnode;
	unsigned int nargs;
	u64 args[8];
};

struct pipe_buf_operations___7;

struct pipe_buffer___7 {
	struct page___7 *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations___7 *ops;
	unsigned int flags;
	long unsigned int private;
};

struct pipe_buf_operations___7 {
	int (*confirm)(struct pipe_inode_info___7 *, struct pipe_buffer___7 *);
	void (*release)(struct pipe_inode_info___7 *, struct pipe_buffer___7 *);
	bool (*try_steal)(struct pipe_inode_info___7 *, struct pipe_buffer___7 *);
	bool (*get)(struct pipe_inode_info___7 *, struct pipe_buffer___7 *);
};

typedef struct bio_vec___7 skb_frag_t___5;

struct skb_shared_info___5 {
	__u8 flags;
	__u8 meta_len;
	__u8 nr_frags;
	__u8 tx_flags;
	short unsigned int gso_size;
	short unsigned int gso_segs;
	struct sk_buff___7 *frag_list;
	struct skb_shared_hwtstamps hwtstamps;
	unsigned int gso_type;
	u32 tskey;
	atomic_t dataref;
	unsigned int xdp_frags_size;
	void *destructor_arg;
	skb_frag_t___5 frags[17];
};

struct trace_event_raw_ovs_do_execute_action {
	struct trace_entry ent;
	void *dpaddr;
	u32 __data_loc_dp_name;
	u32 __data_loc_dev_name;
	void *skbaddr;
	unsigned int len;
	unsigned int data_len;
	unsigned int truesize;
	u8 nr_frags;
	u16 gso_size;
	u16 gso_type;
	u32 ovs_flow_hash;
	u32 recirc_id;
	void *keyaddr;
	u16 key_eth_type;
	u8 key_ct_state;
	u8 key_ct_orig_proto;
	u16 key_ct_zone;
	unsigned int flow_key_valid;
	u8 action_type;
	unsigned int action_len;
	void *action_data;
	u8 is_last;
	char __data[0];
};

struct trace_event_raw_ovs_dp_upcall {
	struct trace_entry ent;
	void *dpaddr;
	u32 __data_loc_dp_name;
	u32 __data_loc_dev_name;
	void *skbaddr;
	unsigned int len;
	unsigned int data_len;
	unsigned int truesize;
	u8 nr_frags;
	u16 gso_size;
	u16 gso_type;
	u32 ovs_flow_hash;
	u32 recirc_id;
	const void *keyaddr;
	u16 key_eth_type;
	u8 key_ct_state;
	u8 key_ct_orig_proto;
	u16 key_ct_zone;
	unsigned int flow_key_valid;
	u8 upcall_cmd;
	u32 upcall_port;
	u16 upcall_mru;
	char __data[0];
};

struct trace_event_data_offsets_ovs_do_execute_action {
	u32 dp_name;
	u32 dev_name;
};

struct trace_event_data_offsets_ovs_dp_upcall {
	u32 dp_name;
	u32 dev_name;
};

typedef void (*btf_trace_ovs_do_execute_action)(void *, struct datapath *, struct sk_buff___7 *, struct sw_flow_key *, const struct nlattr *, int);

typedef void (*btf_trace_ovs_dp_upcall)(void *, struct datapath *, struct sk_buff___7 *, const struct sw_flow_key *, const struct dp_upcall_info *);

struct kset___8;

struct kobj_type___8;

struct kernfs_node___8;

struct kobject___8 {
	const char *name;
	struct list_head entry;
	struct kobject___8 *parent;
	struct kset___8 *kset;
	const struct kobj_type___8 *ktype;
	struct kernfs_node___8 *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct module___8;

struct module_kobject___8 {
	struct kobject___8 kobj;
	struct module___8 *mod;
	struct kobject___8 *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct mod_tree_node___8 {
	struct module___8 *mod;
	struct latch_tree_node node;
};

struct module_layout___8 {
	void *base;
	unsigned int size;
	unsigned int text_size;
	unsigned int ro_size;
	unsigned int ro_after_init_size;
	struct mod_tree_node___8 mtn;
};

struct module_attribute___8;

struct kernel_param___8;

struct module___8 {
	enum module_state state;
	struct list_head list;
	char name[56];
	struct module_kobject___8 mkobj;
	struct module_attribute___8 *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject___8 *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param___8 *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool sig_ok;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	struct module_layout___8 core_layout;
	struct module_layout___8 init_layout;
	struct mod_arch_specific arch;
	long unsigned int taints;
	unsigned int num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map___4 *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	int num_static_call_sites;
	struct static_call_site *static_call_sites;
	int num_kunit_suites;
	struct kunit_suite **kunit_suites;
	bool klp;
	bool klp_alive;
	struct klp_modinfo *klp_info;
	unsigned int printk_index_size;
	struct pi_entry **printk_index_start;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
};

struct dentry___8;

struct super_block___8;

struct file_system_type___8 {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry___8 * (*mount)(struct file_system_type___8 *, int, const char *, void *);
	void (*kill_sb)(struct super_block___8 *);
	struct module___8 *owner;
	struct file_system_type___8 *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

struct page___8;

typedef struct page___8 *pgtable_t___8;

struct address_space___8;

struct page_pool___8;

struct mm_struct___8;

struct dev_pagemap___8;

struct page___8 {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space___8 *mapping;
			long unsigned int index;
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool___8 *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			union {
				long unsigned int dma_addr_upper;
				atomic_long_t pp_frag_count;
			};
		};
		struct {
			long unsigned int compound_head;
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			atomic_t compound_pincount;
			unsigned int compound_nr;
		};
		struct {
			long unsigned int _compound_pad_1;
			long unsigned int _compound_pad_2;
			struct list_head deferred_list;
		};
		struct {
			long unsigned int _pt_pad_1;
			pgtable_t___8 pmd_huge_pte;
			long unsigned int _pt_pad_2;
			union {
				struct mm_struct___8 *pt_mm;
				atomic_t pt_frag_refcount;
			};
			spinlock_t ptl;
		};
		struct {
			struct dev_pagemap___8 *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	long unsigned int memcg_data;
};

struct kernel_param_ops___8 {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param___8 *);
	int (*get)(char *, const struct kernel_param___8 *);
	void (*free)(void *);
};

struct file___8;

struct kiocb___8;

struct iov_iter___8;

struct poll_table_struct___8;

struct vm_area_struct___8;

struct inode___8;

struct file_lock___8;

struct pipe_inode_info___8;

struct seq_file___8;

struct file_operations___8 {
	struct module___8 *owner;
	loff_t (*llseek)(struct file___8 *, loff_t, int);
	ssize_t (*read)(struct file___8 *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file___8 *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb___8 *, struct iov_iter___8 *);
	ssize_t (*write_iter)(struct kiocb___8 *, struct iov_iter___8 *);
	int (*iopoll)(struct kiocb___8 *, struct io_comp_batch *, unsigned int);
	int (*iterate)(struct file___8 *, struct dir_context *);
	int (*iterate_shared)(struct file___8 *, struct dir_context *);
	__poll_t (*poll)(struct file___8 *, struct poll_table_struct___8 *);
	long int (*unlocked_ioctl)(struct file___8 *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file___8 *, unsigned int, long unsigned int);
	int (*mmap)(struct file___8 *, struct vm_area_struct___8 *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode___8 *, struct file___8 *);
	int (*flush)(struct file___8 *, fl_owner_t);
	int (*release)(struct inode___8 *, struct file___8 *);
	int (*fsync)(struct file___8 *, loff_t, loff_t, int);
	int (*fasync)(int, struct file___8 *, int);
	int (*lock)(struct file___8 *, int, struct file_lock___8 *);
	ssize_t (*sendpage)(struct file___8 *, struct page___8 *, int, size_t, loff_t *, int);
	long unsigned int (*get_unmapped_area)(struct file___8 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file___8 *, int, struct file_lock___8 *);
	ssize_t (*splice_write)(struct pipe_inode_info___8 *, struct file___8 *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file___8 *, loff_t *, struct pipe_inode_info___8 *, size_t, unsigned int);
	int (*setlease)(struct file___8 *, long int, struct file_lock___8 **, void **);
	long int (*fallocate)(struct file___8 *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file___8 *, struct file___8 *);
	ssize_t (*copy_file_range)(struct file___8 *, loff_t, struct file___8 *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file___8 *, loff_t, struct file___8 *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file___8 *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

struct page_frag___8 {
	struct page___8 *page;
	__u32 offset;
	__u32 size;
};

struct nsproxy___8;

struct signal_struct___8;

struct bio_list___8;

struct backing_dev_info___8;

struct css_set___8;

struct mem_cgroup___8;

struct vm_struct___8;

struct task_struct___8 {
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct___8 *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	const struct sched_class *sched_class;
	struct rb_node core_node;
	long unsigned int core_cookie;
	unsigned int core_occupation;
	struct task_group *sched_task_group;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_statistics stats;
	struct hlist_head preempt_notifiers;
	unsigned int btrace_seq;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct___8 *mm;
	struct mm_struct___8 *active_mm;
	struct task_rss_stat rss_stat;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	unsigned int sched_psi_wake_requeue: 1;
	int: 28;
	unsigned int sched_remote_wakeup: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int in_user_fault: 1;
	unsigned int in_lru_fault: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_page_owner: 1;
	unsigned int in_eventfd: 1;
	unsigned int pasid_activated: 1;
	unsigned int reported_split_lock: 1;
	unsigned int in_thrashing: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct___8 *real_parent;
	struct task_struct___8 *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct___8 *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid___3 *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_group;
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	struct vtime vtime;
	atomic_t tick_dep_mask;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	struct posix_cputimers_work posix_cputimers_work;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy___8 *nsproxy;
	struct signal_struct___8 *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct audit_context *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct___8 *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	void *journal_info;
	struct bio_list___8 *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct backing_dev_info___8 *backing_dev_info;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	unsigned int psi_flags;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
	struct css_set___8 *cgroups;
	struct list_head cg_list;
	u32 closid;
	u32 rmid;
	struct robust_list_head *robust_list;
	struct compat_robust_list_head *compat_robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	struct perf_event_context *perf_event_ctxp[2];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	long unsigned int preempt_disable_ip;
	struct mempolicy *mempolicy;
	short int il_prev;
	short int pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	long unsigned int numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct numa_group *numa_group;
	long unsigned int *numa_faults;
	long unsigned int total_numa_faults;
	long unsigned int numa_faults_locality[3];
	long unsigned int numa_pages_migrated;
	struct rseq *rseq;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	struct tlbflush_unmap_batch tlb_ubc;
	union {
		refcount_t rcu_users;
		struct callback_head rcu;
	};
	struct pipe_inode_info___8 *splice_pipe;
	struct page_frag___8 task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	int latency_record_count;
	struct latency_record latency_record[32];
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	struct kunit *kunit_test;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace_recursion;
	struct mem_cgroup___8 *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup___8 *active_memcg;
	struct request_queue *throttle_queue;
	struct uprobe_task *utask;
	unsigned int sequential_io;
	unsigned int sequential_io_avg;
	struct kmap_ctrl kmap_ctrl;
	int pagefault_disabled;
	struct task_struct___8 *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct___8 *stack_vm_area;
	refcount_t stack_refcount;
	int patch_state;
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	void *mce_vaddr;
	__u64 mce_kflags;
	u64 mce_addr;
	__u64 mce_ripv: 1;
	__u64 mce_whole_page: 1;
	__u64 __mce_reserved: 62;
	struct callback_head mce_kill_me;
	int mce_count;
	struct llist_head kretprobe_instances;
	struct llist_head rethooks;
	struct callback_head l1d_flush_kill;
	union rv_task_monitor rv[1];
	struct thread_struct___2 thread;
};

struct mm_struct___8 {
	struct {
		struct maple_tree mm_mt;
		long unsigned int (*get_unmapped_area)(struct file___8 *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int mmap_compat_base;
		long unsigned int mmap_compat_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		atomic_t mm_count;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[48];
		struct mm_rss_stat rss_stat;
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct___8 *owner;
		struct user_namespace *user_ns;
		struct file___8 *exe_file;
		struct mmu_notifier_subscriptions *notifier_subscriptions;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		atomic_t tlb_flush_batched;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		u32 pasid;
		long unsigned int ksm_merging_pages;
		long unsigned int ksm_rmap_items;
		struct {
			struct list_head list;
			long unsigned int bitmap;
			struct mem_cgroup___8 *memcg;
		} lru_gen;
	};
	long unsigned int cpu_bitmap[0];
};

struct vm_operations_struct___8;

struct vm_area_struct___8 {
	long unsigned int vm_start;
	long unsigned int vm_end;
	struct mm_struct___8 *vm_mm;
	pgprot_t vm_page_prot;
	long unsigned int vm_flags;
	union {
		struct {
			struct rb_node rb;
			long unsigned int rb_subtree_last;
		} shared;
		struct anon_vma_name *anon_name;
	};
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct___8 *vm_ops;
	long unsigned int vm_pgoff;
	struct file___8 *vm_file;
	void *vm_private_data;
	atomic_long_t swap_readahead_info;
	struct mempolicy *vm_policy;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

struct bin_attribute___8;

struct attribute_group___8 {
	const char *name;
	umode_t (*is_visible)(struct kobject___8 *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject___8 *, struct bin_attribute___8 *, int);
	struct attribute **attrs;
	struct bin_attribute___8 **bin_attrs;
};

struct seq_operations___8 {
	void * (*start)(struct seq_file___8 *, loff_t *);
	void (*stop)(struct seq_file___8 *, void *);
	void * (*next)(struct seq_file___8 *, void *, loff_t *);
	int (*show)(struct seq_file___8 *, void *);
};

struct address_space_operations___8;

struct address_space___8 {
	struct inode___8 *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	struct rw_semaphore i_mmap_rwsem;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations___8 *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t private_lock;
	struct list_head private_list;
	void *private_data;
};

struct device___8;

struct page_pool_params___8 {
	unsigned int flags;
	unsigned int order;
	unsigned int pool_size;
	int nid;
	struct device___8 *dev;
	enum dma_data_direction dma_dir;
	unsigned int max_len;
	unsigned int offset;
	void (*init_callback)(struct page___8 *, void *);
	void *init_arg;
};

struct pp_alloc_cache___8 {
	u32 count;
	struct page___8 *cache[128];
};

struct page_pool___8 {
	struct page_pool_params___8 p;
	struct delayed_work release_dw;
	void (*disconnect)(void *);
	long unsigned int defer_start;
	long unsigned int defer_warn;
	u32 pages_state_hold_cnt;
	unsigned int frag_offset;
	struct page___8 *frag_page;
	long int frag_users;
	u32 xdp_mem_id;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct pp_alloc_cache___8 alloc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct ptr_ring ring;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct dev_pagemap_ops___8;

struct dev_pagemap___8 {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops___8 *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct range ranges[0];
	};
};

struct folio___8 {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space___8 *mapping;
			long unsigned int index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page___8 page;
	};
	long unsigned int _flags_1;
	long unsigned int __head;
	unsigned char _folio_dtor;
	unsigned char _folio_order;
	atomic_t _total_mapcount;
	atomic_t _pincount;
	unsigned int _folio_nr_pages;
};

struct vfsmount___8;

struct path___8 {
	struct vfsmount___8 *mnt;
	struct dentry___8 *dentry;
};

struct file___8 {
	union {
		struct llist_node f_llist;
		struct callback_head f_rcuhead;
		unsigned int f_iocb_flags;
	};
	struct path___8 f_path;
	struct inode___8 *f_inode;
	const struct file_operations___8 *f_op;
	spinlock_t f_lock;
	atomic_long_t f_count;
	unsigned int f_flags;
	fmode_t f_mode;
	struct mutex f_pos_lock;
	loff_t f_pos;
	struct fown_struct___3 f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	u64 f_version;
	void *f_security;
	void *private_data;
	struct hlist_head *f_ep;
	struct address_space___8 *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};

struct vm_fault___8;

struct vm_operations_struct___8 {
	void (*open)(struct vm_area_struct___8 *);
	void (*close)(struct vm_area_struct___8 *);
	int (*may_split)(struct vm_area_struct___8 *, long unsigned int);
	int (*mremap)(struct vm_area_struct___8 *);
	int (*mprotect)(struct vm_area_struct___8 *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault___8 *);
	vm_fault_t (*huge_fault)(struct vm_fault___8 *, enum page_entry_size);
	vm_fault_t (*map_pages)(struct vm_fault___8 *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct___8 *);
	vm_fault_t (*page_mkwrite)(struct vm_fault___8 *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault___8 *);
	int (*access)(struct vm_area_struct___8 *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct___8 *);
	int (*set_policy)(struct vm_area_struct___8 *, struct mempolicy *);
	struct mempolicy * (*get_policy)(struct vm_area_struct___8 *, long unsigned int);
	struct page___8 * (*find_special_page)(struct vm_area_struct___8 *, long unsigned int);
};

struct mem_cgroup___8 {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct page_counter memory;
	union {
		struct page_counter swap;
		struct page_counter memsw;
	};
	struct page_counter kmem;
	struct page_counter tcpmem;
	struct work_struct high_work;
	long unsigned int zswap_max;
	long unsigned int soft_limit;
	struct vmpressure vmpressure;
	bool oom_group;
	bool oom_lock;
	int under_oom;
	int swappiness;
	int oom_kill_disable;
	struct cgroup_file events_file;
	struct cgroup_file events_local_file;
	struct cgroup_file swap_events_file;
	struct mutex thresholds_lock;
	struct mem_cgroup_thresholds thresholds;
	struct mem_cgroup_thresholds memsw_thresholds;
	struct list_head oom_notify;
	long unsigned int move_charge_at_immigrate;
	spinlock_t move_lock;
	long unsigned int move_lock_flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct memcg_vmstats *vmstats;
	atomic_long_t memory_events[9];
	atomic_long_t memory_events_local[9];
	long unsigned int socket_pressure;
	bool tcpmem_active;
	int tcpmem_pressure;
	int kmemcg_id;
	struct obj_cgroup *objcg;
	struct list_head objcg_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	atomic_t moving_account;
	struct task_struct___8 *move_lock_task;
	struct memcg_vmstats_percpu *vmstats_percpu;
	struct list_head cgwb_list;
	struct wb_domain cgwb_domain;
	struct memcg_cgwb_frn cgwb_frn[4];
	struct list_head event_list;
	spinlock_t event_list_lock;
	struct deferred_split deferred_split_queue;
	struct lru_gen_mm_list mm_list;
	struct mem_cgroup_per_node *nodeinfo[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct vm_fault___8 {
	const struct {
		struct vm_area_struct___8 *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page___8 *cow_page;
	struct page___8 *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t___8 prealloc_pte;
};

struct lruvec___8;

struct lru_gen_mm_walk___8 {
	struct lruvec___8 *lruvec;
	long unsigned int max_seq;
	long unsigned int next_addr;
	int nr_pages[40];
	int mm_stats[6];
	int batched;
	bool can_swap;
	bool force_scan;
};

struct pglist_data___8;

struct lruvec___8 {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
	struct lru_gen_struct lrugen;
	struct lru_gen_mm_state mm_state;
	struct pglist_data___8 *pgdat;
};

struct zone___8 {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long int lowmem_reserve[5];
	int node;
	struct pglist_data___8 *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high;
	int pageset_batch;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	long unsigned int present_early_pages;
	long unsigned int cma_pages;
	const char *name;
	long unsigned int nr_isolate_pageblock;
	seqlock_t span_seqlock;
	int initialized;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct free_area free_area[11];
	long unsigned int flags;
	spinlock_t lock;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int percpu_drift_mark;
	long unsigned int compact_cached_free_pfn;
	long unsigned int compact_cached_migrate_pfn[2];
	long unsigned int compact_init_migrate_pfn;
	long unsigned int compact_init_free_pfn;
	unsigned int compact_considered;
	unsigned int compact_defer_shift;
	int compact_order_failed;
	bool compact_blockskip_flush;
	bool contiguous;
	short: 16;
	struct cacheline_padding _pad3_;
	atomic_long_t vm_stat[11];
	atomic_long_t vm_numa_event[6];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct zoneref___8 {
	struct zone___8 *zone;
	int zone_idx;
};

struct zonelist___8 {
	struct zoneref___8 _zonerefs[5121];
};

struct pglist_data___8 {
	struct zone___8 node_zones[5];
	struct zonelist___8 node_zonelists[2];
	int nr_zones;
	spinlock_t node_size_lock;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct mutex kswapd_lock;
	struct task_struct___8 *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct___8 *kcompactd;
	bool proactive_compact_trigger;
	long unsigned int totalreserve_pages;
	long unsigned int min_unmapped_pages;
	long unsigned int min_slab_pages;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct deferred_split deferred_split_queue;
	unsigned int nbp_rl_start;
	long unsigned int nbp_rl_nr_cand;
	unsigned int nbp_threshold;
	unsigned int nbp_th_start;
	long unsigned int nbp_th_nr_cand;
	struct lruvec___8 __lruvec;
	long unsigned int flags;
	struct lru_gen_mm_walk___8 mm_walk;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[43];
	struct memory_tier *memtier;
	long: 64;
	long: 64;
	long: 64;
};

struct core_state___8;

struct signal_struct___8 {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct___8 *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct___8 *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state___8 *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	int posix_timer_id;
	struct list_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid___3 *pids[4];
	atomic_t tick_dep_mask;
	struct pid___3 *tty_old_pgrp;
	int leader;
	struct tty_struct___2 *tty;
	struct autogroup *autogroup;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	unsigned int audit_tty;
	struct tty_audit_buf *tty_audit_buf;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct___8 *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct net___8;

struct nsproxy___8 {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net___8 *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct bio___8;

struct bio_list___8 {
	struct bio___8 *head;
	struct bio___8 *tail;
};

struct bdi_writeback___8 {
	struct backing_dev_info___8 *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	long unsigned int dirty_sleep;
	struct list_head bdi_node;
	struct percpu_ref refcnt;
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css;
	struct cgroup_subsys_state *blkcg_css;
	struct list_head memcg_node;
	struct list_head blkcg_node;
	struct list_head b_attached;
	struct list_head offline_node;
	union {
		struct work_struct release_work;
		struct callback_head rcu;
	};
};

struct backing_dev_info___8 {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	struct bdi_writeback___8 wb;
	struct list_head wb_list;
	struct xarray cgwb_tree;
	struct mutex cgwb_release_mutex;
	struct rw_semaphore wb_switch_rwsem;
	wait_queue_head_t wb_waitq;
	struct device___8 *dev;
	char dev_name[64];
	struct device___8 *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry___8 *debug_dir;
};

struct cgroup___8;

struct css_set___8 {
	struct cgroup_subsys_state *subsys[13];
	refcount_t refcount;
	struct css_set___8 *dom_cset;
	struct cgroup___8 *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[13];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_src_preload_node;
	struct list_head mg_dst_preload_node;
	struct list_head mg_node;
	struct cgroup___8 *mg_src_cgrp;
	struct cgroup___8 *mg_dst_cgrp;
	struct css_set___8 *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
};

struct fasync_struct___8;

struct pipe_buffer___8;

struct pipe_inode_info___8 {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	bool note_loss;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	struct page___8 *tmp_page;
	struct fasync_struct___8 *fasync_readers;
	struct fasync_struct___8 *fasync_writers;
	struct pipe_buffer___8 *bufs;
	struct user_struct *user;
	struct watch_queue *watch_queue;
};

struct vm_struct___8 {
	struct vm_struct___8 *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page___8 **pages;
	unsigned int page_order;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

struct kernfs_elem_symlink___8 {
	struct kernfs_node___8 *target_kn;
};

struct kernfs_ops___8;

struct kernfs_elem_attr___8 {
	const struct kernfs_ops___8 *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node___8 *notify_next;
};

struct kernfs_node___8 {
	atomic_t count;
	atomic_t active;
	struct kernfs_node___8 *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink___8 symlink;
		struct kernfs_elem_attr___8 attr;
	};
	void *priv;
	u64 id;
	short unsigned int flags;
	umode_t mode;
	struct kernfs_iattrs *iattr;
};

struct kernfs_open_file___8;

struct kernfs_ops___8 {
	int (*open)(struct kernfs_open_file___8 *);
	void (*release)(struct kernfs_open_file___8 *);
	int (*seq_show)(struct seq_file___8 *, void *);
	void * (*seq_start)(struct seq_file___8 *, loff_t *);
	void * (*seq_next)(struct seq_file___8 *, void *, loff_t *);
	void (*seq_stop)(struct seq_file___8 *, void *);
	ssize_t (*read)(struct kernfs_open_file___8 *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file___8 *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file___8 *, struct poll_table_struct___8 *);
	int (*mmap)(struct kernfs_open_file___8 *, struct vm_area_struct___8 *);
};

struct seq_file___8 {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations___8 *op;
	int poll_event;
	const struct file___8 *file;
	void *private;
};

struct kernfs_open_file___8 {
	struct kernfs_node___8 *kn;
	struct file___8 *file;
	struct seq_file___8 *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct___8 *vm_ops;
};

typedef void (*poll_queue_proc___8)(struct file___8 *, wait_queue_head_t *, struct poll_table_struct___8 *);

struct poll_table_struct___8 {
	poll_queue_proc___8 _qproc;
	__poll_t _key;
};

struct sock___8;

struct kobj_ns_type_operations___8 {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock___8 *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

struct sk_buff___8;

struct sk_buff_list___8 {
	struct sk_buff___8 *next;
	struct sk_buff___8 *prev;
};

struct sk_buff_head___8 {
	union {
		struct {
			struct sk_buff___8 *next;
			struct sk_buff___8 *prev;
		};
		struct sk_buff_list___8 list;
	};
	__u32 qlen;
	spinlock_t lock;
};

struct socket___8;

struct net_device___8;

struct sock___8 {
	struct sock_common __sk_common;
	struct dst_entry___3 *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	socket_lock_t sk_lock;
	atomic_t sk_drops;
	int sk_rcvlowat;
	struct sk_buff_head___8 sk_error_queue;
	struct sk_buff_head___8 sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	int sk_forward_alloc;
	u32 sk_reserved_mem;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	int sk_rcvbuf;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	struct xfrm_policy *sk_policy[2];
	struct dst_entry___3 *sk_dst_cache;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head___8 sk_write_queue;
	__s32 sk_peek_off;
	int sk_write_pending;
	__u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	long int sk_sndtimeo;
	struct timer_list sk_timer;
	__u32 sk_priority;
	__u32 sk_mark;
	long unsigned int sk_pacing_rate;
	long unsigned int sk_max_pacing_rate;
	struct page_frag___8 sk_frag;
	netdev_features_t sk_route_caps;
	int sk_gso_type;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	__u32 sk_txhash;
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_userlocks: 4;
	u8 sk_pacing_shift;
	u16 sk_type;
	u16 sk_protocol;
	u16 sk_gso_max_segs;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	u8 sk_txrehash;
	u8 sk_prefer_busy_poll;
	u16 sk_busy_poll_budget;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid___3 *sk_peer_pid;
	const struct cred *sk_peer_cred;
	long int sk_rcvtimeo;
	ktime_t sk_stamp;
	u16 sk_tsflags;
	u8 sk_shutdown;
	atomic_t sk_tskey;
	atomic_t sk_zckey;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	struct socket___8 *sk_socket;
	void *sk_user_data;
	void *sk_security;
	struct sock_cgroup_data sk_cgrp_data;
	struct mem_cgroup___8 *sk_memcg;
	void (*sk_state_change)(struct sock___8 *);
	void (*sk_data_ready)(struct sock___8 *);
	void (*sk_write_space)(struct sock___8 *);
	void (*sk_error_report)(struct sock___8 *);
	int (*sk_backlog_rcv)(struct sock___8 *, struct sk_buff___8 *);
	struct sk_buff___8 * (*sk_validate_xmit_skb)(struct sock___8 *, struct net_device___8 *, struct sk_buff___8 *);
	void (*sk_destruct)(struct sock___8 *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
	struct hlist_node sk_bind2_node;
};

struct bin_attribute___8 {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space___8 * (*f_mapping)();
	ssize_t (*read)(struct file___8 *, struct kobject___8 *, struct bin_attribute___8 *, char *, loff_t, size_t);
	ssize_t (*write)(struct file___8 *, struct kobject___8 *, struct bin_attribute___8 *, char *, loff_t, size_t);
	int (*mmap)(struct file___8 *, struct kobject___8 *, struct bin_attribute___8 *, struct vm_area_struct___8 *);
};

struct sysfs_ops___8 {
	ssize_t (*show)(struct kobject___8 *, struct attribute *, char *);
	ssize_t (*store)(struct kobject___8 *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops___8;

struct kset___8 {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject___8 kobj;
	const struct kset_uevent_ops___8 *uevent_ops;
};

struct kobj_type___8 {
	void (*release)(struct kobject___8 *);
	const struct sysfs_ops___8 *sysfs_ops;
	const struct attribute_group___8 **default_groups;
	const struct kobj_ns_type_operations___8 * (*child_ns_type)(struct kobject___8 *);
	const void * (*namespace)(struct kobject___8 *);
	void (*get_ownership)(struct kobject___8 *, kuid_t *, kgid_t *);
};

struct kset_uevent_ops___8 {
	int (* const filter)(struct kobject___8 *);
	const char * (* const name)(struct kobject___8 *);
	int (* const uevent)(struct kobject___8 *, struct kobj_uevent_env *);
};

struct kparam_array___8;

struct kernel_param___8 {
	const char *name;
	struct module___8 *mod;
	const struct kernel_param_ops___8 *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array___8 *arr;
	};
};

struct kparam_array___8 {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops___8 *ops;
	void *elem;
};

struct module_attribute___8 {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute___8 *, struct module_kobject___8 *, char *);
	ssize_t (*store)(struct module_attribute___8 *, struct module_kobject___8 *, const char *, size_t);
	void (*setup)(struct module___8 *, const char *);
	int (*test)(struct module___8 *);
	void (*free)(struct module___8 *);
};

struct dentry_operations___8;

struct dentry___8 {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry___8 *d_parent;
	struct qstr d_name;
	struct inode___8 *d_inode;
	unsigned char d_iname[32];
	struct lockref d_lockref;
	const struct dentry_operations___8 *d_op;
	struct super_block___8 *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct list_head d_child;
	struct list_head d_subdirs;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

struct inode_operations___8;

struct inode___8 {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations___8 *i_op;
	struct super_block___8 *i_sb;
	struct address_space___8 *i_mapping;
	void *i_security;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback___8 *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations___8 *i_fop;
		void (*free_inode)(struct inode___8 *);
	};
	struct file_lock_context *i_flctx;
	struct address_space___8 i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info___8 *i_pipe;
		struct cdev___2 *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_info *i_crypt_info;
	struct fsverity_info *i_verity_info;
	void *i_private;
};

struct dentry_operations___8 {
	int (*d_revalidate)(struct dentry___8 *, unsigned int);
	int (*d_weak_revalidate)(struct dentry___8 *, unsigned int);
	int (*d_hash)(const struct dentry___8 *, struct qstr *);
	int (*d_compare)(const struct dentry___8 *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry___8 *);
	int (*d_init)(struct dentry___8 *);
	void (*d_release)(struct dentry___8 *);
	void (*d_prune)(struct dentry___8 *);
	void (*d_iput)(struct dentry___8 *, struct inode___8 *);
	char * (*d_dname)(struct dentry___8 *, char *, int);
	struct vfsmount___8 * (*d_automount)(struct path___8 *);
	int (*d_manage)(const struct path___8 *, bool);
	struct dentry___8 * (*d_real)(struct dentry___8 *, const struct inode___8 *);
	long: 64;
	long: 64;
	long: 64;
};

struct quota_format_type___8;

struct mem_dqinfo___8 {
	struct quota_format_type___8 *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};

struct quota_format_ops___8;

struct quota_info___8 {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode___8 *files[3];
	struct mem_dqinfo___8 info[3];
	const struct quota_format_ops___8 *ops[3];
};

struct rcuwait___8 {
	struct task_struct___8 *task;
};

struct percpu_rw_semaphore___8 {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait___8 writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers___8 {
	int frozen;
	wait_queue_head_t wait_unfrozen;
	struct percpu_rw_semaphore___8 rw_sem[3];
};

struct shrink_control___8;

struct shrinker___8 {
	long unsigned int (*count_objects)(struct shrinker___8 *, struct shrink_control___8 *);
	long unsigned int (*scan_objects)(struct shrinker___8 *, struct shrink_control___8 *);
	long int batch;
	int seeks;
	unsigned int flags;
	struct list_head list;
	int id;
	atomic_long_t *nr_deferred;
};

struct super_operations___8;

struct dquot_operations___8;

struct quotactl_ops___8;

struct block_device___8;

struct super_block___8 {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type___8 *s_type;
	const struct super_operations___8 *s_op;
	const struct dquot_operations___8 *dq_op;
	const struct quotactl_ops___8 *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry___8 *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	void *s_security;
	const struct xattr_handler **s_xattr;
	const struct fscrypt_operations *s_cop;
	struct fscrypt_keyring *s_master_keys;
	const struct fsverity_operations *s_vop;
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device___8 *s_bdev;
	struct backing_dev_info___8 *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info___8 s_dquot;
	struct sb_writers___8 s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	__u32 s_fsnotify_mask;
	struct fsnotify_mark_connector *s_fsnotify_marks;
	char s_id[32];
	uuid_t s_uuid;
	unsigned int s_max_links;
	fmode_t s_mode;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations___8 *s_d_op;
	struct shrinker___8 s_shrink;
	atomic_long_t s_remove_count;
	atomic_long_t s_fsnotify_connectors;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	long: 32;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 64;
	long: 64;
};

struct vfsmount___8 {
	struct dentry___8 *mnt_root;
	struct super_block___8 *mnt_sb;
	int mnt_flags;
	struct user_namespace *mnt_userns;
};

struct shrink_control___8 {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup___8 *memcg;
};

struct cgroup___8 {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	struct kernfs_node___8 *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	struct cgroup_file psi_files[4];
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[13];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[13];
	struct cgroup___8 *dom_cgrp;
	struct cgroup___8 *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group *psi;
	struct cgroup_bpf bpf;
	atomic_t congestion_count;
	struct cgroup_freezer_state freezer;
	struct cgroup___8 *ancestors[0];
};

struct core_thread___8 {
	struct task_struct___8 *task;
	struct core_thread___8 *next;
};

struct core_state___8 {
	atomic_t nr_threads;
	struct core_thread___8 dumper;
	struct completion startup;
};

struct kiocb___8 {
	struct file___8 *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb___8 *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	struct wait_page_queue *ki_waitq;
};

struct iattr___8 {
	unsigned int ia_valid;
	umode_t ia_mode;
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file___8 *ia_file;
};

struct dquot___8 {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block___8 *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};

struct quota_format_type___8 {
	int qf_fmt_id;
	const struct quota_format_ops___8 *qf_ops;
	struct module___8 *qf_owner;
	struct quota_format_type___8 *qf_next;
};

struct quota_format_ops___8 {
	int (*check_quota_file)(struct super_block___8 *, int);
	int (*read_file_info)(struct super_block___8 *, int);
	int (*write_file_info)(struct super_block___8 *, int);
	int (*free_file_info)(struct super_block___8 *, int);
	int (*read_dqblk)(struct dquot___8 *);
	int (*commit_dqblk)(struct dquot___8 *);
	int (*release_dqblk)(struct dquot___8 *);
	int (*get_next_id)(struct super_block___8 *, struct kqid *);
};

struct dquot_operations___8 {
	int (*write_dquot)(struct dquot___8 *);
	struct dquot___8 * (*alloc_dquot)(struct super_block___8 *, int);
	void (*destroy_dquot)(struct dquot___8 *);
	int (*acquire_dquot)(struct dquot___8 *);
	int (*release_dquot)(struct dquot___8 *);
	int (*mark_dirty)(struct dquot___8 *);
	int (*write_info)(struct super_block___8 *, int);
	qsize_t * (*get_reserved_space)(struct inode___8 *);
	int (*get_projid)(struct inode___8 *, kprojid_t *);
	int (*get_inode_usage)(struct inode___8 *, qsize_t *);
	int (*get_next_id)(struct super_block___8 *, struct kqid *);
};

struct quotactl_ops___8 {
	int (*quota_on)(struct super_block___8 *, int, int, const struct path___8 *);
	int (*quota_off)(struct super_block___8 *, int);
	int (*quota_enable)(struct super_block___8 *, unsigned int);
	int (*quota_disable)(struct super_block___8 *, unsigned int);
	int (*quota_sync)(struct super_block___8 *, int);
	int (*set_info)(struct super_block___8 *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block___8 *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block___8 *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block___8 *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block___8 *, struct qc_state *);
	int (*rm_xquota)(struct super_block___8 *, unsigned int);
};

struct writeback_control___8;

struct address_space_operations___8 {
	int (*writepage)(struct page___8 *, struct writeback_control___8 *);
	int (*read_folio)(struct file___8 *, struct folio___8 *);
	int (*writepages)(struct address_space___8 *, struct writeback_control___8 *);
	bool (*dirty_folio)(struct address_space___8 *, struct folio___8 *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file___8 *, struct address_space___8 *, loff_t, unsigned int, struct page___8 **, void **);
	int (*write_end)(struct file___8 *, struct address_space___8 *, loff_t, unsigned int, unsigned int, struct page___8 *, void *);
	sector_t (*bmap)(struct address_space___8 *, sector_t);
	void (*invalidate_folio)(struct folio___8 *, size_t, size_t);
	bool (*release_folio)(struct folio___8 *, gfp_t);
	void (*free_folio)(struct folio___8 *);
	ssize_t (*direct_IO)(struct kiocb___8 *, struct iov_iter___8 *);
	int (*migrate_folio)(struct address_space___8 *, struct folio___8 *, struct folio___8 *, enum migrate_mode);
	int (*launder_folio)(struct folio___8 *);
	bool (*is_partially_uptodate)(struct folio___8 *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio___8 *, bool *, bool *);
	int (*error_remove_page)(struct address_space___8 *, struct page___8 *);
	int (*swap_activate)(struct swap_info_struct *, struct file___8 *, sector_t *);
	void (*swap_deactivate)(struct file___8 *);
	int (*swap_rw)(struct kiocb___8 *, struct iov_iter___8 *);
};

struct writeback_control___8 {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_fscache_wb: 1;
	unsigned int no_cgroup_owner: 1;
	unsigned int punt_to_cgroup: 1;
	struct swap_iocb **swap_plug;
	struct bdi_writeback___8 *wb;
	struct inode___8 *inode;
	int wb_id;
	int wb_lcand_id;
	int wb_tcand_id;
	size_t wb_bytes;
	size_t wb_lcand_bytes;
	size_t wb_tcand_bytes;
};

struct bio_vec___8;

struct iov_iter___8 {
	u8 iter_type;
	bool nofault;
	bool data_source;
	bool user_backed;
	union {
		size_t iov_offset;
		int last_offset;
	};
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec___8 *bvec;
		struct xarray *xarray;
		struct pipe_inode_info___8 *pipe;
		void *ubuf;
	};
	union {
		long unsigned int nr_segs;
		struct {
			unsigned int head;
			unsigned int start_head;
		};
		loff_t xarray_start;
	};
};

struct inode_operations___8 {
	struct dentry___8 * (*lookup)(struct inode___8 *, struct dentry___8 *, unsigned int);
	const char * (*get_link)(struct dentry___8 *, struct inode___8 *, struct delayed_call *);
	int (*permission)(struct user_namespace *, struct inode___8 *, int);
	struct posix_acl * (*get_acl)(struct inode___8 *, int, bool);
	int (*readlink)(struct dentry___8 *, char *, int);
	int (*create)(struct user_namespace *, struct inode___8 *, struct dentry___8 *, umode_t, bool);
	int (*link)(struct dentry___8 *, struct inode___8 *, struct dentry___8 *);
	int (*unlink)(struct inode___8 *, struct dentry___8 *);
	int (*symlink)(struct user_namespace *, struct inode___8 *, struct dentry___8 *, const char *);
	int (*mkdir)(struct user_namespace *, struct inode___8 *, struct dentry___8 *, umode_t);
	int (*rmdir)(struct inode___8 *, struct dentry___8 *);
	int (*mknod)(struct user_namespace *, struct inode___8 *, struct dentry___8 *, umode_t, dev_t);
	int (*rename)(struct user_namespace *, struct inode___8 *, struct dentry___8 *, struct inode___8 *, struct dentry___8 *, unsigned int);
	int (*setattr)(struct user_namespace *, struct dentry___8 *, struct iattr___8 *);
	int (*getattr)(struct user_namespace *, const struct path___8 *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry___8 *, char *, size_t);
	int (*fiemap)(struct inode___8 *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode___8 *, struct timespec64 *, int);
	int (*atomic_open)(struct inode___8 *, struct dentry___8 *, struct file___8 *, unsigned int, umode_t);
	int (*tmpfile)(struct user_namespace *, struct inode___8 *, struct file___8 *, umode_t);
	int (*set_acl)(struct user_namespace *, struct inode___8 *, struct posix_acl *, int);
	int (*fileattr_set)(struct user_namespace *, struct dentry___8 *, struct fileattr *);
	int (*fileattr_get)(struct dentry___8 *, struct fileattr *);
	long: 64;
};

struct file_lock_operations___8 {
	void (*fl_copy_lock)(struct file_lock___8 *, struct file_lock___8 *);
	void (*fl_release_private)(struct file_lock___8 *);
};

struct lock_manager_operations___8;

struct file_lock___8 {
	struct file_lock___8 *fl_blocker;
	struct list_head fl_list;
	struct hlist_node fl_link;
	struct list_head fl_blocked_requests;
	struct list_head fl_blocked_member;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	unsigned int fl_pid;
	int fl_link_cpu;
	wait_queue_head_t fl_wait;
	struct file___8 *fl_file;
	loff_t fl_start;
	loff_t fl_end;
	struct fasync_struct___8 *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct file_lock_operations___8 *fl_ops;
	const struct lock_manager_operations___8 *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
	} fl_u;
};

struct lock_manager_operations___8 {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock___8 *);
	int (*lm_grant)(struct file_lock___8 *, int);
	bool (*lm_break)(struct file_lock___8 *);
	int (*lm_change)(struct file_lock___8 *, int, struct list_head *);
	void (*lm_setup)(struct file_lock___8 *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lock___8 *);
	bool (*lm_lock_expirable)(struct file_lock___8 *);
	void (*lm_expire_lock)();
};

struct fasync_struct___8 {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct___8 *fa_next;
	struct file___8 *fa_file;
	struct callback_head fa_rcu;
};

struct super_operations___8 {
	struct inode___8 * (*alloc_inode)(struct super_block___8 *);
	void (*destroy_inode)(struct inode___8 *);
	void (*free_inode)(struct inode___8 *);
	void (*dirty_inode)(struct inode___8 *, int);
	int (*write_inode)(struct inode___8 *, struct writeback_control___8 *);
	int (*drop_inode)(struct inode___8 *);
	void (*evict_inode)(struct inode___8 *);
	void (*put_super)(struct super_block___8 *);
	int (*sync_fs)(struct super_block___8 *, int);
	int (*freeze_super)(struct super_block___8 *);
	int (*freeze_fs)(struct super_block___8 *);
	int (*thaw_super)(struct super_block___8 *);
	int (*unfreeze_fs)(struct super_block___8 *);
	int (*statfs)(struct dentry___8 *, struct kstatfs *);
	int (*remount_fs)(struct super_block___8 *, int *, char *);
	void (*umount_begin)(struct super_block___8 *);
	int (*show_options)(struct seq_file___8 *, struct dentry___8 *);
	int (*show_devname)(struct seq_file___8 *, struct dentry___8 *);
	int (*show_path)(struct seq_file___8 *, struct dentry___8 *);
	int (*show_stats)(struct seq_file___8 *, struct dentry___8 *);
	ssize_t (*quota_read)(struct super_block___8 *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block___8 *, int, const char *, size_t, loff_t);
	struct dquot___8 ** (*get_dquots)(struct inode___8 *);
	long int (*nr_cached_objects)(struct super_block___8 *, struct shrink_control___8 *);
	long int (*free_cached_objects)(struct super_block___8 *, struct shrink_control___8 *);
};

struct wakeup_source___8;

struct dev_pm_info___8 {
	pm_message_t power_state;
	unsigned int can_wakeup: 1;
	unsigned int async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	struct list_head entry;
	struct completion completion;
	struct wakeup_source___8 *wakeup;
	bool wakeup_path: 1;
	bool syscore: 1;
	bool no_pm_callbacks: 1;
	unsigned int must_resume: 1;
	unsigned int may_skip_resume: 1;
	struct hrtimer suspend_timer;
	u64 timer_expires;
	struct work_struct work;
	wait_queue_head_t wait_queue;
	struct wake_irq *wakeirq;
	atomic_t usage_count;
	atomic_t child_count;
	unsigned int disable_depth: 3;
	unsigned int idle_notification: 1;
	unsigned int request_pending: 1;
	unsigned int deferred_resume: 1;
	unsigned int needs_force_resume: 1;
	unsigned int runtime_auto: 1;
	bool ignore_children: 1;
	unsigned int no_callbacks: 1;
	unsigned int irq_safe: 1;
	unsigned int use_autosuspend: 1;
	unsigned int timer_autosuspends: 1;
	unsigned int memalloc_noio: 1;
	unsigned int links_count;
	enum rpm_request request;
	enum rpm_status runtime_status;
	enum rpm_status last_status;
	int runtime_error;
	int autosuspend_delay;
	u64 last_busy;
	u64 active_time;
	u64 suspended_time;
	u64 accounting_timestamp;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device___8 *, s32);
	struct dev_pm_qos *qos;
};

struct device_type___8;

struct bus_type___8;

struct device_driver___8;

struct dev_pm_domain___8;

struct fwnode_handle___8;

struct class___8;

struct device___8 {
	struct kobject___8 kobj;
	struct device___8 *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type___8 *type;
	struct bus_type___8 *bus;
	struct device_driver___8 *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info___8 power;
	struct dev_pm_domain___8 *pm_domain;
	struct em_perf_domain *em_pd;
	struct dev_pin_info *pins;
	struct dev_msi_info msi;
	const struct dma_map_ops *dma_ops;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct cma *cma_area;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle___8 *fwnode;
	int numa_node;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	struct class___8 *class;
	const struct attribute_group___8 **groups;
	void (*release)(struct device___8 *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
};

struct block_device___8 {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	bool bd_read_only;
	dev_t bd_dev;
	atomic_t bd_openers;
	struct inode___8 *bd_inode;
	struct super_block___8 *bd_super;
	void *bd_claiming;
	struct device___8 bd_device;
	void *bd_holder;
	int bd_holders;
	bool bd_write_holder;
	struct kobject___8 *bd_holder_dir;
	u8 bd_partno;
	spinlock_t bd_size_lock;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	int bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct super_block___8 *bd_fsfreeze_sb;
	struct partition_meta_info *bd_meta_info;
};

typedef void bio_end_io_t___8(struct bio___8 *);

struct bio_vec___8 {
	struct page___8 *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct bio___8 {
	struct bio___8 *bi_next;
	struct block_device___8 *bi_bdev;
	blk_opf_t bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t___8 *bi_end_io;
	void *bi_private;
	struct blkcg_gq *bi_blkg;
	struct bio_issue bi_issue;
	u64 bi_iocost_cost;
	struct bio_crypt_ctx *bi_crypt_context;
	union {
		struct bio_integrity_payload *bi_integrity;
	};
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec___8 *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec___8 bi_inline_vecs[0];
};

struct dev_pagemap_ops___8 {
	void (*page_free)(struct page___8 *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault___8 *);
	int (*memory_failure)(struct dev_pagemap___8 *, long unsigned int, long unsigned int, int);
};

struct ubuf_info___8;

struct msghdr___8 {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter___8 msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb___8 *msg_iocb;
	struct ubuf_info___8 *msg_ubuf;
	int (*sg_from_iter)(struct sock___8 *, struct sk_buff___8 *, struct iov_iter___8 *, size_t);
};

struct ubuf_info___8 {
	void (*callback)(struct sk_buff___8 *, struct ubuf_info___8 *, bool);
	refcount_t refcnt;
	u8 flags;
};

struct sk_buff___8 {
	union {
		struct {
			struct sk_buff___8 *next;
			struct sk_buff___8 *prev;
			union {
				struct net_device___8 *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	union {
		struct sock___8 *sk;
		int ip_defrag_offset;
	};
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff___8 *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 tc_skip_classify: 1;
			__u8 tc_at_ingress: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u8 scm_io_uring: 1;
			__u16 tc_index;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			u16 alloc_cpu;
			__u32 secmark;
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
};

struct socket_wq___8 {
	wait_queue_head_t wait;
	struct fasync_struct___8 *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
	long: 64;
};

struct proto_ops___8;

struct socket___8 {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file___8 *file;
	struct sock___8 *sk;
	const struct proto_ops___8 *ops;
	long: 64;
	long: 64;
	long: 64;
	struct socket_wq___8 wq;
};

typedef int (*sk_read_actor_t___8)(read_descriptor_t *, struct sk_buff___8 *, unsigned int, size_t);

typedef int (*skb_read_actor_t___8)(struct sock___8 *, struct sk_buff___8 *);

struct proto_ops___8 {
	int family;
	struct module___8 *owner;
	int (*release)(struct socket___8 *);
	int (*bind)(struct socket___8 *, struct sockaddr *, int);
	int (*connect)(struct socket___8 *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket___8 *, struct socket___8 *);
	int (*accept)(struct socket___8 *, struct socket___8 *, int, bool);
	int (*getname)(struct socket___8 *, struct sockaddr *, int);
	__poll_t (*poll)(struct file___8 *, struct socket___8 *, struct poll_table_struct___8 *);
	int (*ioctl)(struct socket___8 *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct socket___8 *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket___8 *, void *, bool, bool);
	int (*listen)(struct socket___8 *, int);
	int (*shutdown)(struct socket___8 *, int);
	int (*setsockopt)(struct socket___8 *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket___8 *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file___8 *, struct socket___8 *);
	int (*sendmsg)(struct socket___8 *, struct msghdr___8 *, size_t);
	int (*recvmsg)(struct socket___8 *, struct msghdr___8 *, size_t, int);
	int (*mmap)(struct file___8 *, struct socket___8 *, struct vm_area_struct___8 *);
	ssize_t (*sendpage)(struct socket___8 *, struct page___8 *, int, size_t, int);
	ssize_t (*splice_read)(struct socket___8 *, loff_t *, struct pipe_inode_info___8 *, size_t, unsigned int);
	int (*set_peek_off)(struct sock___8 *, int);
	int (*peek_len)(struct socket___8 *);
	int (*read_sock)(struct sock___8 *, read_descriptor_t *, sk_read_actor_t___8);
	int (*read_skb)(struct sock___8 *, skb_read_actor_t___8);
	int (*sendpage_locked)(struct sock___8 *, struct page___8 *, int, size_t, int);
	int (*sendmsg_locked)(struct sock___8 *, struct msghdr___8 *, size_t);
	int (*set_rcvlowat)(struct sock___8 *, int);
};

struct net___8 {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	atomic_t dev_unreg_count;
	unsigned int dev_base_seq;
	int ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node cleanup_list;
	struct key_tag *key_domain;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
	struct sock___8 *rtnl;
	struct sock___8 *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device___8 *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_ipv4___3 ipv4;
	struct netns_ipv6___3 ipv6;
	struct netns_ieee802154_lowpan___3 ieee802154_lowpan;
	struct netns_sctp___3 sctp;
	struct netns_nf___2 nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct netns_ft ft;
	struct sk_buff_head___8 wext_nlevents;
	struct net_generic *gen;
	struct netns_bpf bpf;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_xfrm xfrm;
	u64 net_cookie;
	struct netns_ipvs *ipvs;
	struct netns_mpls mpls;
	struct netns_can can;
	struct netns_xdp xdp;
	struct netns_mctp mctp;
	struct sock___8 *crypto_nlsk;
	struct sock___8 *diag_nlsk;
	struct netns_smc smc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct dev_pm_ops___8 {
	int (*prepare)(struct device___8 *);
	void (*complete)(struct device___8 *);
	int (*suspend)(struct device___8 *);
	int (*resume)(struct device___8 *);
	int (*freeze)(struct device___8 *);
	int (*thaw)(struct device___8 *);
	int (*poweroff)(struct device___8 *);
	int (*restore)(struct device___8 *);
	int (*suspend_late)(struct device___8 *);
	int (*resume_early)(struct device___8 *);
	int (*freeze_late)(struct device___8 *);
	int (*thaw_early)(struct device___8 *);
	int (*poweroff_late)(struct device___8 *);
	int (*restore_early)(struct device___8 *);
	int (*suspend_noirq)(struct device___8 *);
	int (*resume_noirq)(struct device___8 *);
	int (*freeze_noirq)(struct device___8 *);
	int (*thaw_noirq)(struct device___8 *);
	int (*poweroff_noirq)(struct device___8 *);
	int (*restore_noirq)(struct device___8 *);
	int (*runtime_suspend)(struct device___8 *);
	int (*runtime_resume)(struct device___8 *);
	int (*runtime_idle)(struct device___8 *);
};

struct wakeup_source___8 {
	const char *name;
	int id;
	struct list_head entry;
	spinlock_t lock;
	struct wake_irq *wakeirq;
	struct timer_list timer;
	long unsigned int timer_expires;
	ktime_t total_time;
	ktime_t max_time;
	ktime_t last_time;
	ktime_t start_prevent_time;
	ktime_t prevent_sleep_time;
	long unsigned int event_count;
	long unsigned int active_count;
	long unsigned int relax_count;
	long unsigned int expire_count;
	long unsigned int wakeup_count;
	struct device___8 *dev;
	bool active: 1;
	bool autosleep_enabled: 1;
};

struct dev_pm_domain___8 {
	struct dev_pm_ops___8 ops;
	int (*start)(struct device___8 *);
	void (*detach)(struct device___8 *, bool);
	int (*activate)(struct device___8 *);
	void (*sync)(struct device___8 *);
	void (*dismiss)(struct device___8 *);
};

struct bus_type___8 {
	const char *name;
	const char *dev_name;
	struct device___8 *dev_root;
	const struct attribute_group___8 **bus_groups;
	const struct attribute_group___8 **dev_groups;
	const struct attribute_group___8 **drv_groups;
	int (*match)(struct device___8 *, struct device_driver___8 *);
	int (*uevent)(struct device___8 *, struct kobj_uevent_env *);
	int (*probe)(struct device___8 *);
	void (*sync_state)(struct device___8 *);
	void (*remove)(struct device___8 *);
	void (*shutdown)(struct device___8 *);
	int (*online)(struct device___8 *);
	int (*offline)(struct device___8 *);
	int (*suspend)(struct device___8 *, pm_message_t);
	int (*resume)(struct device___8 *);
	int (*num_vf)(struct device___8 *);
	int (*dma_configure)(struct device___8 *);
	void (*dma_cleanup)(struct device___8 *);
	const struct dev_pm_ops___8 *pm;
	const struct iommu_ops *iommu_ops;
	struct subsys_private *p;
	struct lock_class_key lock_key;
	bool need_parent_lock;
};

struct device_driver___8 {
	const char *name;
	struct bus_type___8 *bus;
	struct module___8 *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device___8 *);
	void (*sync_state)(struct device___8 *);
	int (*remove)(struct device___8 *);
	void (*shutdown)(struct device___8 *);
	int (*suspend)(struct device___8 *, pm_message_t);
	int (*resume)(struct device___8 *);
	const struct attribute_group___8 **groups;
	const struct attribute_group___8 **dev_groups;
	const struct dev_pm_ops___8 *pm;
	void (*coredump)(struct device___8 *);
	struct driver_private *p;
};

struct device_type___8 {
	const char *name;
	const struct attribute_group___8 **groups;
	int (*uevent)(struct device___8 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___8 *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device___8 *);
	const struct dev_pm_ops___8 *pm;
};

struct class___8 {
	const char *name;
	struct module___8 *owner;
	const struct attribute_group___8 **class_groups;
	const struct attribute_group___8 **dev_groups;
	struct kobject___8 *dev_kobj;
	int (*dev_uevent)(struct device___8 *, struct kobj_uevent_env *);
	char * (*devnode)(struct device___8 *, umode_t *);
	void (*class_release)(struct class___8 *);
	void (*dev_release)(struct device___8 *);
	int (*shutdown_pre)(struct device___8 *);
	const struct kobj_ns_type_operations___8 *ns_type;
	const void * (*namespace)(struct device___8 *);
	void (*get_ownership)(struct device___8 *, kuid_t *, kgid_t *);
	const struct dev_pm_ops___8 *pm;
	struct subsys_private *p;
};

struct fwnode_operations___8;

struct fwnode_handle___8 {
	struct fwnode_handle___8 *secondary;
	const struct fwnode_operations___8 *ops;
	struct device___8 *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

struct fwnode_reference_args___8;

struct fwnode_endpoint___8;

struct fwnode_operations___8 {
	struct fwnode_handle___8 * (*get)(struct fwnode_handle___8 *);
	void (*put)(struct fwnode_handle___8 *);
	bool (*device_is_available)(const struct fwnode_handle___8 *);
	const void * (*device_get_match_data)(const struct fwnode_handle___8 *, const struct device___8 *);
	bool (*device_dma_supported)(const struct fwnode_handle___8 *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle___8 *);
	bool (*property_present)(const struct fwnode_handle___8 *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle___8 *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle___8 *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle___8 *);
	const char * (*get_name_prefix)(const struct fwnode_handle___8 *);
	struct fwnode_handle___8 * (*get_parent)(const struct fwnode_handle___8 *);
	struct fwnode_handle___8 * (*get_next_child_node)(const struct fwnode_handle___8 *, struct fwnode_handle___8 *);
	struct fwnode_handle___8 * (*get_named_child_node)(const struct fwnode_handle___8 *, const char *);
	int (*get_reference_args)(const struct fwnode_handle___8 *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args___8 *);
	struct fwnode_handle___8 * (*graph_get_next_endpoint)(const struct fwnode_handle___8 *, struct fwnode_handle___8 *);
	struct fwnode_handle___8 * (*graph_get_remote_endpoint)(const struct fwnode_handle___8 *);
	struct fwnode_handle___8 * (*graph_get_port_parent)(struct fwnode_handle___8 *);
	int (*graph_parse_endpoint)(const struct fwnode_handle___8 *, struct fwnode_endpoint___8 *);
	void * (*iomap)(struct fwnode_handle___8 *, int);
	int (*irq_get)(const struct fwnode_handle___8 *, unsigned int);
	int (*add_links)(struct fwnode_handle___8 *);
};

struct fwnode_endpoint___8 {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle___8 *local_fwnode;
};

struct fwnode_reference_args___8 {
	struct fwnode_handle___8 *fwnode;
	unsigned int nargs;
	u64 args[8];
};

struct pipe_buf_operations___8;

struct pipe_buffer___8 {
	struct page___8 *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations___8 *ops;
	unsigned int flags;
	long unsigned int private;
};

struct pipe_buf_operations___8 {
	int (*confirm)(struct pipe_inode_info___8 *, struct pipe_buffer___8 *);
	void (*release)(struct pipe_inode_info___8 *, struct pipe_buffer___8 *);
	bool (*try_steal)(struct pipe_inode_info___8 *, struct pipe_buffer___8 *);
	bool (*get)(struct pipe_inode_info___8 *, struct pipe_buffer___8 *);
};

enum ip_conntrack_events {
	IPCT_NEW = 0,
	IPCT_RELATED = 1,
	IPCT_DESTROY = 2,
	IPCT_REPLY = 3,
	IPCT_ASSURED = 4,
	IPCT_PROTOINFO = 5,
	IPCT_HELPER = 6,
	IPCT_MARK = 7,
	IPCT_SEQADJ = 8,
	IPCT_NATSEQADJ = 8,
	IPCT_SECMARK = 9,
	IPCT_LABEL = 10,
	IPCT_SYNPROXY = 11,
	__IPCT_MAX = 12,
};

typedef rx_handler_result_t rx_handler_func_t___8(struct sk_buff___8 **);

struct net_device___8 {
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
	long unsigned int state;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct list_head ptype_specific;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	unsigned int flags;
	long long unsigned int priv_flags;
	const struct net_device_ops *netdev_ops;
	int ifindex;
	short unsigned int gflags;
	short unsigned int hard_header_len;
	unsigned int mtu;
	short unsigned int needed_headroom;
	short unsigned int needed_tailroom;
	netdev_features_t features;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	netdev_features_t gso_partial_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct iw_handler_def *wireless_handlers;
	struct iw_public_data *wireless_data;
	const struct ethtool_ops *ethtool_ops;
	const struct l3mdev_ops *l3mdev_ops;
	const struct ndisc_ops *ndisc_ops;
	const struct xfrmdev_ops *xfrmdev_ops;
	const struct tlsdev_ops *tlsdev_ops;
	const struct header_ops *header_ops;
	unsigned char operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	short unsigned int padded;
	spinlock_t addr_list_lock;
	int irq;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset___8 *queues_kset;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct inet6_dev *ip6_ptr;
	struct vlan_info *vlan_info;
	struct dsa_port *dsa_ptr;
	struct tipc_bearer *tipc_ptr;
	void *atalk_ptr;
	void *ax25_ptr;
	struct wireless_dev *ieee80211_ptr;
	struct wpan_dev *ieee802154_ptr;
	struct mpls_dev *mpls_ptr;
	struct mctp_dev *mctp_ptr;
	const unsigned char *dev_addr;
	struct netdev_rx_queue *_rx;
	unsigned int num_rx_queues;
	unsigned int real_num_rx_queues;
	struct bpf_prog *xdp_prog;
	long unsigned int gro_flush_timeout;
	int napi_defer_hard_irqs;
	unsigned int gro_max_size;
	rx_handler_func_t___8 *rx_handler;
	void *rx_handler_data;
	struct mini_Qdisc *miniq_ingress;
	struct netdev_queue *ingress_queue;
	struct nf_hook_entries___2 *nf_hooks_ingress;
	unsigned char broadcast[32];
	struct cpu_rmap *rx_cpu_rmap;
	struct hlist_node index_hlist;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netdev_queue *_tx;
	unsigned int num_tx_queues;
	unsigned int real_num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct xps_dev_maps *xps_maps[2];
	struct mini_Qdisc *miniq_egress;
	struct nf_hook_entries___2 *nf_hooks_egress;
	struct hlist_head qdisc_hash[16];
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	int *pcpu_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	enum {
		NETREG_UNINITIALIZED___8 = 0,
		NETREG_REGISTERED___8 = 1,
		NETREG_UNREGISTERING___8 = 2,
		NETREG_UNREGISTERED___8 = 3,
		NETREG_RELEASED___8 = 4,
		NETREG_DUMMY___8 = 5,
	} reg_state: 8;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED___8 = 0,
		RTNL_LINK_INITIALIZING___8 = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device___8 *);
	struct netpoll_info *npinfo;
	possible_net_t nd_net;
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	struct garp_port *garp_port;
	struct mrp_port *mrp_port;
	struct dm_hw_stat_delta *dm_private;
	struct device___8 dev;
	const struct attribute_group___8 *sysfs_groups[4];
	const struct attribute_group___8 *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	unsigned int gso_max_size;
	unsigned int tso_max_size;
	u16 gso_max_segs;
	u16 tso_max_segs;
	const struct dcbnl_rtnl_ops *dcbnl_ops;
	s16 num_tc;
	struct netdev_tc_txq tc_to_txq[16];
	u8 prio_tc_map[16];
	unsigned int fcoe_ddp_xid;
	struct netprio_map *priomap;
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	unsigned int wol_enabled: 1;
	unsigned int threaded: 1;
	struct list_head net_notifier_list;
	const struct macsec_ops *macsec_ops;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	long: 64;
	long: 64;
	long: 64;
};

enum ovs_ct_attr {
	OVS_CT_ATTR_UNSPEC = 0,
	OVS_CT_ATTR_COMMIT = 1,
	OVS_CT_ATTR_ZONE = 2,
	OVS_CT_ATTR_MARK = 3,
	OVS_CT_ATTR_LABELS = 4,
	OVS_CT_ATTR_HELPER = 5,
	OVS_CT_ATTR_NAT = 6,
	OVS_CT_ATTR_FORCE_COMMIT = 7,
	OVS_CT_ATTR_EVENTMASK = 8,
	OVS_CT_ATTR_TIMEOUT = 9,
	__OVS_CT_ATTR_MAX = 10,
};

enum ovs_nat_attr {
	OVS_NAT_ATTR_UNSPEC = 0,
	OVS_NAT_ATTR_SRC = 1,
	OVS_NAT_ATTR_DST = 2,
	OVS_NAT_ATTR_IP_MIN = 3,
	OVS_NAT_ATTR_IP_MAX = 4,
	OVS_NAT_ATTR_PROTO_MIN = 5,
	OVS_NAT_ATTR_PROTO_MAX = 6,
	OVS_NAT_ATTR_PERSISTENT = 7,
	OVS_NAT_ATTR_PROTO_HASH = 8,
	OVS_NAT_ATTR_PROTO_RANDOM = 9,
	__OVS_NAT_ATTR_MAX = 10,
};

enum ovs_ct_limit_cmd {
	OVS_CT_LIMIT_CMD_UNSPEC = 0,
	OVS_CT_LIMIT_CMD_SET = 1,
	OVS_CT_LIMIT_CMD_DEL = 2,
	OVS_CT_LIMIT_CMD_GET = 3,
};

enum ovs_ct_limit_attr {
	OVS_CT_LIMIT_ATTR_UNSPEC = 0,
	OVS_CT_LIMIT_ATTR_ZONE_LIMIT = 1,
	__OVS_CT_LIMIT_ATTR_MAX = 2,
};

struct ovs_zone_limit {
	int zone_id;
	__u32 limit;
	__u32 count;
};

typedef unsigned int nf_hookfn___4(void *, struct sk_buff___8 *, const struct nf_hook_state *);

enum nf_nat_manip_type {
	NF_NAT_MANIP_SRC = 0,
	NF_NAT_MANIP_DST = 1,
};

struct nf_conntrack_l4proto {
	u_int8_t l4proto;
	bool allow_clash;
	u16 nlattr_size;
	bool (*can_early_drop)(const struct nf_conn *);
	int (*to_nlattr)(struct sk_buff___8 *, struct nlattr *, struct nf_conn *, bool);
	int (*from_nlattr)(struct nlattr **, struct nf_conn *);
	int (*tuple_to_nlattr)(struct sk_buff___8 *, const struct nf_conntrack_tuple *);
	unsigned int (*nlattr_tuple_size)();
	int (*nlattr_to_tuple)(struct nlattr **, struct nf_conntrack_tuple *, u_int32_t);
	const struct nla_policy *nla_policy;
	struct {
		int (*nlattr_to_obj)(struct nlattr **, struct net___8 *, void *);
		int (*obj_to_nlattr)(struct sk_buff___8 *, const void *);
		u16 obj_size;
		u16 nlattr_max;
		const struct nla_policy *nla_policy;
	} ctnl_timeout;
	void (*print_conntrack)(struct seq_file___8 *, struct nf_conn *);
};

struct nf_conntrack_expect_policy;

struct nf_conntrack_helper {
	struct hlist_node hnode;
	char name[16];
	refcount_t refcnt;
	struct module___8 *me;
	const struct nf_conntrack_expect_policy *expect_policy;
	struct nf_conntrack_tuple tuple;
	int (*help)(struct sk_buff___8 *, unsigned int, struct nf_conn *, enum ip_conntrack_info);
	void (*destroy)(struct nf_conn *);
	int (*from_nlattr)(struct nlattr *, struct nf_conn *);
	int (*to_nlattr)(struct sk_buff___8 *, const struct nf_conn *);
	unsigned int expect_class_max;
	unsigned int flags;
	unsigned int queue_num;
	u16 data_len;
	char nat_mod_name[16];
};

struct nf_conntrack_expect_policy {
	unsigned int max_expected;
	unsigned int timeout;
	char name[16];
};

struct nf_conntrack_ecache {
	long unsigned int cache;
	u16 ctmask;
	u16 expmask;
	u32 missed;
	u32 portid;
};

struct nf_conn_help {
	struct nf_conntrack_helper *helper;
	struct hlist_head expectations;
	u8 expecting[4];
	int: 32;
	char data[32];
};

struct nf_ct_seqadj {
	u32 correction_pos;
	s32 offset_before;
	s32 offset_after;
};

struct nf_conn_seqadj {
	struct nf_ct_seqadj seq[2];
};

struct nf_ct_timeout {
	__u16 l3num;
	const struct nf_conntrack_l4proto *l4proto;
	char data[0];
};

struct nf_conn_timeout {
	struct nf_ct_timeout *timeout;
};

struct nf_nat_pptp {
	__be16 pns_call_id;
	__be16 pac_call_id;
};

struct nf_nat_range2 {
	unsigned int flags;
	union nf_inet_addr min_addr;
	union nf_inet_addr max_addr;
	union nf_conntrack_man_proto min_proto;
	union nf_conntrack_man_proto max_proto;
	union nf_conntrack_man_proto base_proto;
};

union nf_conntrack_nat_help {
	struct nf_nat_pptp nat_pptp_info;
};

struct nf_conn_nat {
	union nf_conntrack_nat_help help;
	int masq_index;
};

struct nf_conn_act_ct_ext {
	int ifindex[2];
};

struct nf_conncount_data;

struct ovs_ct_limit_info {
	u32 default_limit;
	struct hlist_head *limits;
	struct nf_conncount_data *data;
};

struct ovs_ct_len_tbl {
	int maxlen;
	int minlen;
};

struct md_mark {
	u32 value;
	u32 mask;
};

struct md_labels {
	struct ovs_key_ct_labels value;
	struct ovs_key_ct_labels mask;
};

enum ovs_ct_nat {
	OVS_CT_NAT = 1,
	OVS_CT_SRC_NAT = 2,
	OVS_CT_DST_NAT = 4,
};

struct ovs_conntrack_info {
	struct nf_conntrack_helper *helper;
	struct nf_conntrack_zone zone;
	struct nf_conn *ct;
	u8 commit: 1;
	u8 nat: 3;
	u8 force: 1;
	u8 have_eventmask: 1;
	u16 family;
	u32 eventmask;
	struct md_mark mark;
	struct md_labels labels;
	char timeout[32];
	struct nf_ct_timeout *nf_ct_timeout;
	struct nf_nat_range2 range;
};

struct ovs_ct_limit {
	struct hlist_node hlist_node;
	struct callback_head rcu;
	u16 zone;
	u32 limit;
};


#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __OPENVSWITCH_H__ */
