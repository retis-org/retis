#!/bin/bash
set -e

# Script generating a minimal vmlinux.h header to be included in the eBPF part.
# The goal is to have all required information to probe information from kernel
# data structures.

PAHOLE="${PAHOLE:-pahole} -q"

# Modules containing types we need (in addition to the base kernel).
modules="
	openvswitch
	nf_tables
"

for mod in $modules; do
	modprobe $mod
done

# List of types we use in the eBPF part (for probing mostly), excluding sk_buff
# (always included below).
types="
	`# Base types`
	s8
	s16
	__s32
	s32
	bool

	`# Core probes`
	bpf_kprobe_multi_link
	bpf_map_type
	bpf_raw_tp_link
	bpf_raw_tracepoint_args
	kprobe_opcode_t
	pt_regs

	`# ct collector`
	nf_conn
	nf_conn_labels
	ip_conntrack_dir
	nf_ct_ext
	nf_ct_ext_id

	`# nft collector`
	nft_base_chain
	nft_pktinfo
	nft_rule
	nft_rule_dp
	nft_rule_dp_last
	nft_table
	nft_traceinfo
	nft_verdict
	nft_verdicts

	`# ovs collector`
	__una_u32
	dp_upcall_info
	ovs_action_attr
	ovs_conntrack_info
	ovs_ct_nat
	nlattr
	sw_flow
	sw_flow_key

	`# skb collector`
	ethhdr
	iphdr
	ipv6hdr
	net
	net_device
	skb_drop_reason
	skb_shared_info
	sock
	vlan_ethhdr
"

classes="sk_buff"
for t in $types; do
	classes="$classes,$t"
done

# Anonymous enums defined in the core kernel we use in the eBPF probes.
enums_vmlinux="
	BPF_F_FAST_STACK_CMP
	BPF_NOEXIST
	BPF_RB_FORCE_WAKEUP
	IPPROTO_UDP
	NFPROTO_IPV4
"

cat <<EOF > vmlinux.h
#if !defined(__GENERIC_VMLINUX_H__) || defined(__VMLINUX_H__)
#error "Please do not include arch specific vmlinux header. Use #include <vmlinux.h>, instead."
#endif

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

 
#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

EOF

$PAHOLE /sys/kernel/btf/* --compile -C $classes >> vmlinux.h

for e in $enums_vmlinux; do
	# Not using --compile here to avoid redefinition of types. If any type is a
	# prerequisite here, add it to $types.
	$PAHOLE /sys/kernel/btf/vmlinux --contains_enumerator=$e >> vmlinux.h
	echo -e ";\n" >> vmlinux.h
done

# Some common extra (non-type) definitions are needed, provide them.
cat <<EOF >> vmlinux.h
#define true 1
#define false 0

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
EOF
