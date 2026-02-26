#!/bin/bash
source $(dirname $0)/include/lib.sh
source $(dirname $0)/include/helpers.sh

drop_sanity() {
	two_ns

	$retis collect -o -c skb-drop,skb,dev -f tcp \
		--cmd 'ip netns exec ns0 socat -T1 - TCP:10.0.42.2:443'

        $retis stats > stats
        grep -q "Number of events: 1" stats
        grep -q "raw_tracepoint/skb:kfree_skb: 1" stats
        first_ts=$(grep "First event at:" stats | cut -d ":" -f 2-)
        last_ts=$(grep "Last event at:" stats | cut -d ":" -f 2-)
        [[ "$first_ts" !=  "" ]]
        [[ "$first_ts" ==  "$last_ts" ]]

	cat >test.py <<EOF
from helpers import assert_events_present

expected_events = [
    {
        "common": {
            "task": {
                "comm": "socat",
            },
        },
        "kernel": {
            "probe_type": "raw_tracepoint",
            "symbol": "skb:kfree_skb",
        },
        "dev": {
            "name": "veth10",
        },
        "skb-drop": {
            "drop_reason": "NO_SOCKET",
        },
        "parsed_packet": {
            "ip": {
                "dst": "10.0.42.2",
                "proto": "tcp",
                "src": "10.0.42.1",
                "ttl": "64",
            },
            "tcp": {
                "dport": "https",
                "flags": "s",
            },
        },
    },
]

assert_events_present("retis.data", expected_events)
EOF
	python test.py
}

run_tests drop_sanity
