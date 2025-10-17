#!/bin/bash

# Allow more verbosity for debugging purposes.
[ "$V" == "1" ] && set -x

CLEANUP_LIST=()

# Add a command to be run at cleanup time.
cleanup() {
	CLEANUP_LIST+=("$@")
}

# Cleanup all resources. Called between each test.
cleanup_all() {
	for ((i=${#CLEANUP_LIST[@]} - 1; i >= 0; i--)); do
		${CLEANUP_LIST[$i]}
	done
	CLEANUP_LIST=()
}

# Run the Retis debug binary.
export retis=$(git rev-parse --show-toplevel)/target/debug/retis

# Allow importing custom Python modules.
export PYTHONPATH="${PYTHONPATH}:$(git rev-parse --show-toplevel)/tests/next/include"

# Create network namespaces. Take a list of network namespace names as the
# input.
add_ns() {
	for ns in $@; do
		ip netns add $ns
		ip -n $ns link set lo up
		cleanup "ip netns del $ns | xargs -r kill"
	done
}

# Add a veth pair.
add_veth_pair() {
	veth0_name=$1
	veth0_ns=$2	# Optional ("" to skip)
	veth1_name=$3
	veth1_ns=$4	# Optional ("" to skip)

	[ ! -z "$veth0_ns" ] && ns0="netns $veth0_ns" || true
	[ ! -z "$veth1_ns" ] && ns1="netns $veth1_ns" || true

	ip link add $veth0_name $ns0 type veth peer name $veth1_name $ns1
	ip -net ns0 link set $veth0_name up
	ip -net ns1 link set $veth1_name up

	# Cleanup interfaces in the main netns.
	[ -z "$veth0_ns" ] && cleanup "ip link del $veth0_name" || true
	[ -z "$veth1_ns" ] && cleanup "ip link del $veth1_name" || true
}

# Run a list of tests. Takes the test functions as an argument.
run_tests() {
	# Allow overriding the tests list to run.
	tests="${TESTS:-$@}"
	for t in $tests; do
		tmpdir=$(mktemp -d -t retis-test-XXXX)
		cleanup "rm -rf $tmpdir"
		cd $tmpdir

		echo -n "Running $t test..."
		[ "$V" != "1" ] && $t >log 2>&1 || $t
		echo " OK"
		cleanup_all
	done
}

# Called when the script encounters an error.
__error() {
	exec 1>&21; exec 2>&22
	echo -e " FAIL\n"; [ -f log ] && cat log

	# Start a shell to inspect failures if configured to.
	[ "$INSPECT_ERR" = "1" ] && {
		echo "Starting shell for inspection..."
		PS1="inspect> " bash --norc
	}

	rm -f log
}
exec 21>&1; exec 22>&1
trap __error ERR

# Clean up all resources. Called when the script exists.
__cleanup() {
	trap - ERR; set +e
	cleanup_all &>/dev/null
}
trap __cleanup EXIT

# Errors are considered a CI a failure unless manually handled.
set -Ee
