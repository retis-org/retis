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

        # Check stats contain all 3 rotation blocks
        $retis stats > stats
        [ $(grep -c "Split index" stats) == 3 ]
        [ $(grep -c "Probes" stats) == 3 ]
        [ $(grep -c "First event" stats)  == 3 ]
        [ $(grep -c "Last event" stats) == 3 ]
        [ $(grep -c "Retis cmdline" stats) == 1 ]

        # Test each split reports increasing first and last timestamps
        # by performing lexicographic comparisons.
        first_ts="0"
        last_ts="0"
        for split in $(seq 0 2); do
            $retis stats retis.data.${split}> stats_${split}
            f_ts=$(grep "First event at:" stats_${split} | cut -d ":" -f 2- | xargs)
            l_ts=$(grep "Last event at:" stats_${split} | cut -d ":" -f 2- | xargs)
            [[ "$f_ts" < "$l_ts" ]] || [[ "$f_ts" == "$l_ts" ]]
            [[ "$f_ts" > "$first_ts" ]]
            [[ "$l_ts" > "$last_ts" ]]
            first_ts=$f_ts
            last_ts=$l_ts
        done
}

run_tests rotation_by_size
