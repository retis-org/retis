#!/bin/bash

set -e
RETIS_TAG=${RETIS_TAG:-latest}

# Auto-detect the available runtime.
if command -v podman >/dev/null; then
	runtime=podman
	extra_args="--pull=newer"

	# Retis cannot run in an unprivileged container to collect events.
	if [[ $(id -u) -ne 0 && $@ =~ "collect" ]]; then
		echo "Error: Retis collection cannot run in an unprivileged container."
		exit -1
	fi
elif command -v docker >/dev/null; then
	runtime=docker
else
	echo "No container runtime detected. Please install 'podman' or 'docker'."
	exit -1
fi

# Look for a kernel configuration file.
if [ ! -z $RETIS_KCONF ]; then
	kconfig=$RETIS_KCONF
elif [ -f /proc/config.gz ]; then
	kconfig=/proc/config.gz
elif [ -f /boot/config-$(uname -r) ]; then
	kconfig=/boot/config-$(uname -r)
elif [ -f /lib/modules/$(uname -r)/config ]; then
	kconfig=/lib/modules/$(uname -r)/config
else
	echo "Could not auto-detect kernel configuration location:"
	echo "You can set the RETIS_KCONF environment variable to manually set it."
	exit -1
fi

# Map local config if exist.
local_conf=$HOME/.config/retis
[ -d $local_conf ] && local_conf="-v $local_conf:/root/.config/retis:ro" || local_conf=""

# Determine if OVS is installed on the host and, if so, mount its binary.
if binary=$(command -v ovs-vswitchd); then
	ovs_binary_mount="-v ${binary}:${binary}:ro"
fi

# Run the Retis container.
exec $runtime run $extra_args -e TERM --privileged --rm --pid=host \
      --cap-add SYS_ADMIN --cap-add BPF --cap-add SYSLOG \
      -v /sys/kernel/btf:/sys/kernel/btf:ro \
      -v /sys/kernel/debug:/sys/kernel/debug:ro \
      -v $kconfig:/kconfig:ro \
      -v $(pwd):/data:rw \
      $local_conf \
      $ovs_binary_mount \
      quay.io/retis/retis:$RETIS_TAG "$@"
