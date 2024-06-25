#!/bin/bash
set -e

btf_dir=/sys/kernel/btf
modules="\
	openvswitch \
	nf_tables \
"

# First load required modules
for mod in $modules; do
	modprobe $mod
done

tmpdir=$(mktemp -d)

# Generate vmlinux header.
bpftool btf dump file $btf_dir/vmlinux format c > $tmpdir/vmlinux.h

# Generate module headers and remove duplicate information from vmlinux one.
for mod in $modules; do
	bpftool btf dump file $btf_dir/$mod format c > $tmpdir/$mod.h

	(diff --changed-group-format='%>' --unchanged-group-format='' \
		$tmpdir/vmlinux.h $tmpdir/$mod.h || true) > $tmpdir/${mod}_dedup.h
done

# Generate a combined vmlinux.h:
# 1. Add a define guard again direct use.
# 2. Get the vmlinux.h content without the trailing pragmas.
# 3. Get all modules header contents.
# 4. Add back the trailing pragmas.

cat <<EOF > vmlinux.h
#if !defined(__GENERIC_VMLINUX_H__) || defined(__VMLINUX_H__)
#error "Please do not include arch specific vmlinux header. Use #include <vmlinux.h>, instead."
#endif

EOF

head -n-5 $tmpdir/vmlinux.h >> vmlinux.h

for mod in $modules; do
	cat $tmpdir/${mod}_dedup.h >> vmlinux.h
done

cat <<EOF >> vmlinux.h
#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
EOF
