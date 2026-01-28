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
		eval ${CLEANUP_LIST[$i]}
	done
	CLEANUP_LIST=()
}

# Run the Retis debug binary. Export it so it's usable in the inspection shell.
export retis=$(git rev-parse --show-toplevel)/target/debug/retis
[ ! -x $retis ] && { echo "Please build Retis first ('make')"; exit 1; }

# Allow importing custom Python modules.
export PYTHONPATH="${PYTHONPATH}:$(git rev-parse --show-toplevel)/tests/next/include"

# Create network namespaces. Take a list of network namespace names as the
# input.
add_ns() {
	for ns in $@; do
		ip netns add $ns
		ip -n $ns link set lo up
		cleanup "ip netns pids $ns | xargs -r kill; ip netns del $ns"
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

	[ ! -z "$veth0_ns" ] && ns0="-net $veth0_ns" || true
	[ ! -z "$veth1_ns" ] && ns1="-net $veth1_ns" || true

	ip $ns0 link set $veth0_name up
	ip $ns1 link set $veth1_name up

	# Cleanup interfaces in the main netns.
	[ -z "$veth0_ns" ] && cleanup "ip link del $veth0_name" || true
	[ -z "$veth1_ns" ] && cleanup "ip link del $veth1_name" || true
}

# Allow capturing stdout/stderr while running tests. Tests should exit on
# errors so we can't redirect the test function outputs directly and have to
# redirect the main stdout/stderr fds. We also have to keep additional fds
# pointing to the original stdout/stderr fds for restoring things after a test
# completes or fails.
exec 21>&1; exec 22>&2
__capture_stdout() {
	[ "$V" != "1" ] && exec 1>log 2>&1 || true
}
__restore_stdout() {
	exec 1>&21 2>&22
}

# Run a list of tests. Takes the test functions as an argument.
run_tests() {
	# Allow overriding the tests list to run.
	tests="${TESTS:-$@}"
	for t in $tests; do
		# Do not error on unknown tests to allow `TESTS` use with
		# `make functional-tests`.
		typeset -f $t >/dev/null || continue
		[ "$LIST_TESTS" == "1" ] && { echo $t; continue; }

		tmpdir=$(mktemp -d -t retis-test-XXXX)
		cleanup "rm -rf $tmpdir"
		cd $tmpdir

		echo -n "Running $t test..."
		__RET=0
		__capture_stdout
		$t
		__restore_stdout
		[ "$__RET" == "42" ] && echo " SKIP" || echo " OK"
		cleanup_all
	done
}

require() {
	set +e
	$@ &>/dev/null || __RET=42
	set -e
	[ $__RET != 0 ] && return 1
	return 0
}

# Called when the script encounters an error.
__error() {
	__restore_stdout
	echo -e " FAIL\n"; [ -f log ] && cat log

	# Start a shell to inspect failures if configured to.
	[ "$INSPECT_ERR" = "1" ] && {
		echo "Starting shell for inspection..."
		PS1="inspect> " bash --norc
	}

	rm -f log
}
trap __error ERR

# Clean up all resources. Called when the script exists.
__cleanup() {
	trap - ERR; set +e
	cleanup_all &>/dev/null
}
trap __cleanup EXIT

# Provide a simple breakpoint for stopping at a given line.
BREAK() { INSPECT_ERR=1; false; }

# Errors are considered a CI a failure unless manually handled.
set -Ee
