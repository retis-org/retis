#!/bin/bash

set -e
RETIS_IMAGE=${RETIS_IMAGE:-quay.io/retis/retis}
RETIS_TAG=${RETIS_TAG:-latest}

errcho() {
	>&2 echo $*
}

# Auto-detect the available runtime.
if command -v podman >/dev/null; then
	runtime=podman
	extra_args="--pull=newer"

	# Retis cannot run in an unprivileged container to collect events.
	if [[ $(id -u) -ne 0 && $@ =~ "collect" ]]; then
		errcho "Error: Retis collection cannot run in an unprivileged container."
		exit -1
	fi
elif command -v docker >/dev/null; then
	docker pull $RETIS_IMAGE:$RETIS_TAG &>/dev/null
	runtime=docker
	# Mount permission is disabled in the default Docker AppArmor profile,
	# but is needed to mount tracefs/debugfs.
	[[ $@ =~ "--allow-system-changes" ]] && \
		extra_args="--security-opt apparmor=unconfined"
else
	errcho "No container runtime detected. Please install 'podman' or 'docker'."
	exit -1
fi

# We can't use a pseudo-tty (see `-t` option in `man podman run`) when using
# a command outputting a specific format to stdout (which could be piped into
# another utility parsing it), like the pcap command. This is because an extra
# EOL char is added (see commit 9f3361ac39c3).
[[ ! $@ =~ "pcap" ]] && term_opts="-it"

# Map well-known kernel configuration files.
kconfig_map=""
for kconfig in /proc/config.gz \
               /boot/config-$(uname -r) \
               /lib/modules/$(uname -r)/config; do
    if [ -f $kconfig ]; then
        kconfig_map="$kconfig_map -v ${kconfig}:${kconfig}:ro"
	# Map the first item to /kconfig to support older versions of the container
	# image.
	[[ -z $kconfig_legacy_map ]] && kconfig_legacy_map="-v ${kconfig}:/kconfig:ro"
    fi
done
if [[ -z $kconfig_map ]]; then
	errcho "WARN: Could not auto-detect kernel configuration location. "
	errcho "You can place your configuration file in the current directory and use the '--kconf' option"
fi

# Find tracefs; keep mounting debugfs for older RETIS_TAG.
[ -d /sys/kernel/tracing ] && tracefs="-v /sys/kernel/tracing:/sys/kernel/tracing:ro"
[ -d /sys/kernel/debug ] && debugfs="-v /sys/kernel/debug:/sys/kernel/debug:ro"

# Map local config if exist.
local_conf=$HOME/.config/retis
[ -d $local_conf ] && local_conf="-v $local_conf:/root/.config/retis:ro" || local_conf=""

# Determine if OVS is installed on the host and, if so, mount its binary.
if binary=$(command -v ovs-vswitchd); then
	ovs_binary_mount="-v ${binary}:${binary}:ro"
fi

# Determine if OVS unixctl is available on the host and, if so, mount it.
if [ -f ${OVS_RUNDIR:-/var/run/openvswitch}/ovs-vswitchd.pid ]; then
	ovs_rundir_mount="-v ${OVS_RUNDIR:-/var/run/openvswitch}:/var/run/openvswitch:rw"
fi

# Run the Retis container.
exec $runtime run $extra_args $term_opts --rm --pid=host \
      --cap-drop all --security-opt no-new-privileges --read-only --net none \
      --cap-add SYS_ADMIN --cap-add BPF --cap-add CAP_PERFMON --cap-add SYSLOG \
      --cap-add DAC_OVERRIDE --cap-add CAP_NET_ADMIN --cap-add SYS_PTRACE \
      -e PAGER -e NOPAGER -e TERM -e LC_ALL="C.UTF-8" \
      -v /sys/kernel/btf:/sys/kernel/btf:ro \
      $tracefs $debugfs \
      -v $(pwd):/data:rw \
      $kconfig_legacy_map $kconfig_map \
      $local_conf \
      $ovs_binary_mount \
      $ovs_rundir_mount \
      $RETIS_IMAGE:$RETIS_TAG "$@"
