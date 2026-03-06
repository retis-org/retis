#!/bin/bash
source $(dirname $0)/include/lib.sh
source $(dirname $0)/include/helpers.sh

stop_after_sanity() {
	two_ns

	$retis collect -o -c skb -p net:netif_receive_skb \
		-f 'icmp and src host 10.0.42.2 and icmp[icmptype] == icmp-echoreply' \
		--stop-after 2 \
		--cmd 'ip netns exec ns0 ping -c 10 -i 0.2 -w 10 10.0.42.2'

	cat >test.py <<EOF
from helpers import assert_events_present, events_to_json

assert_events_present("retis.data", [
    {
        "kernel": {"symbol": "net:netif_receive_skb"},
        "parsed_packet": {
            "icmp": {"type": "echo-reply"},
            "ip": {"src": "10.0.42.2"},
        },
    },
    {
        "kernel": {"symbol": "net:netif_receive_skb"},
        "parsed_packet": {
            "icmp": {"type": "echo-reply"},
            "ip": {"src": "10.0.42.2"},
        },
    },
])

user_events = [e for e in events_to_json("retis.data") if "kernel" in e]
assert len(user_events) == 2, f"Expected 2 events, got {len(user_events)}"
EOF
	python test.py
}

run_tests stop_after_sanity
