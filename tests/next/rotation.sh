#!/bin/bash
source $(dirname $0)/include/lib.sh
source $(dirname $0)/include/helpers.sh

rotation_by_size() {
	two_ns

	ip netns exec ns1 socat TCP-LISTEN:80 /dev/null &
	$retis collect -o --out-rotate 1MB \
		-f "host 10.0.42.1" \
		--cmd "head -c10M /dev/zero | ip netns exec ns0 socat - TCP:10.0.42.2:80; sleep 0.1"

	# Rotation file names should be used.
	[ ! -f retis.data ]

	# Let's require at least 3 rotations to ease further tests.
	[ -f retis.data.0 ]
	[ -f retis.data.1 ]
	[ -f retis.data.2 ]

	# Make sure out files are under 1MB.
	[ $(stat --printf="%s" retis.data.0) -le 1000000 ]
	[ $(stat --printf="%s" retis.data.1) -le 1000000 ]
	[ $(stat --printf="%s" retis.data.2) -le 1000000 ]

	# Check reading rotated events.

	out=$($retis print)
	echo $out | grep "file id 0"
	echo $out | grep "file id 1"
	echo $out | grep "file id 2"

	out=$($retis print retis.data.1)
	echo $out | grep -v "file id 0"
	echo $out | grep "file id 1"
	echo $out | grep -v "file id 2"

	out=$($retis print retis.data.1..)
	echo $out | grep -v "file id 0"
	echo $out | grep "file id 1"
	echo $out | grep "file id 2"
}

run_tests rotation_by_size
