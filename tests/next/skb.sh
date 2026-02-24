#!/bin/bash
source $(dirname $0)/include/lib.sh
source $(dirname $0)/include/helpers.sh

skb_sanity() {
	require $retis python -h || return 0
	two_ns

	$retis collect -o -c skb,dev,ns -f icmp -p ip_rcv \
		--cmd 'ip netns exec ns0 ping -c1 10.0.42.2; sleep 1'

	[ $(wc -l < retis.data) == 3 ]
	cat >test.py <<EOF
r = reader.events()
next(r)	# Skip startup event
e = next(r)
assert(e.kernel.symbol == "ip_rcv")
e = next(r)
assert(e.kernel.symbol == "ip_rcv")
EOF
	$retis python test.py
}

skb_tcp_cc() {
	two_ns

	# FIXME: stop using STDIN
	ip netns exec ns1 socat TCP-LISTEN:80 /dev/null &
	$retis collect -o -c skb,dev --skb-sections all \
		-f 'tcp port 80 or arp' -p net:netif_rx \
		--cmd 'ip netns exec ns0 socat -T1 STDIN TCP:10.0.42.2:80; sleep 1'

	cat >test.py <<EOF
from helpers import assert_events_present

expected_events = [
    # ARP req
    {
        "common": {
            "task": {
                "comm": "socat",
            },
        },
        "kernel": {
            "probe_type": "raw_tracepoint",
            "symbol": "net:netif_rx",
        },
        "dev": {
            "name": "veth10",
        },
        "parsed_packet": {
            "ethernet": {
                "type": "arp",
            },
            "arp": {
                "op": "who-has",
                "psrc": "10.0.42.1",
                "pdst": "10.0.42.2",
            },
        },
    },
    # ARP rep
    {
        "common": {
            "task": {
                "comm": "socat",
            },
        },
        "kernel": {
            "probe_type": "raw_tracepoint",
            "symbol": "net:netif_rx",
        },
        "dev": {
            "name": "veth01",
        },
        "parsed_packet": {
            "arp": {
                "op": "is-at",
                "psrc": "10.0.42.2",
                "pdst": "10.0.42.1",
            },
            "ethernet": {
                "type": "arp",
            },
        },
    },
    # SYN
    {
        "common": {
            "task": {
                "comm": "socat",
            },
        },
        "kernel": {
            "probe_type": "raw_tracepoint",
            "symbol": "net:netif_rx",
        },
        "dev": {
            "name": "veth10",
        },
        "parsed_packet": {
            "ethernet": {
                "type": "ipv4",
            },
            "ip": {
                "dst": "10.0.42.2",
                "proto": "tcp",
                "src": "10.0.42.1",
                "ttl": "64",
            },
            "tcp": {
                "dport": "http",
                "flags": "s",
            },
        },
    },
    # SYN,ACK
    {
        "common": {
            "task": {
                "comm": "socat",
            },
        },
        "kernel": {
            "probe_type": "raw_tracepoint",
            "symbol": "net:netif_rx",
        },
        "dev": {
            "name": "veth01",
        },
        "parsed_packet": {
            "ethernet": {
                "type": "ipv4",
            },
            "ip": {
                "dst": "10.0.42.1",
                "proto": "tcp",
                "src": "10.0.42.2",
                "ttl": "64",
            },
            "tcp": {
                "flags": "sa",
                "sport": "http",
            },
        },
    },
    # ACK
    {
        "common": {
            "task": {
                "comm": "socat",
            },
        },
        "kernel": {
            "probe_type": "raw_tracepoint",
            "symbol": "net:netif_rx",
        },
        "dev": {
            "name": "veth10",
        },
        "parsed_packet": {
            "ethernet": {
                "type": "ipv4",
            },
            "ip": {
                "dst": "10.0.42.2",
                "proto": "tcp",
                "src": "10.0.42.1",
                "ttl": "64",
            },
            "tcp": {
                "dport": "http",
                "flags": "a",
            },
        },
    },
    # -> FIN
    {
        "common": {
            "task": {
                "comm": "socat",
            },
        },
        "kernel": {
            "probe_type": "raw_tracepoint",
            "symbol": "net:netif_rx",
        },
        "dev": {
            "name": "veth01",
        },
        "parsed_packet": {
            "ethernet": {
                "type": "ipv4",
            },
            "ip": {
                "dst": "10.0.42.1",
                "proto": "tcp",
                "src": "10.0.42.2",
                "ttl": "64",
            },
            "tcp": {
                "flags": "fa",
                "sport": "http",
            },
        },
    },
    # -> ACK
    {
        "kernel": {
            "probe_type": "raw_tracepoint",
            "symbol": "net:netif_rx",
        },
        "dev": {
            "name": "veth10",
        },
        "parsed_packet": {
            "ethernet": {
                "type": "ipv4",
            },
            "ip": {
                "dst": "10.0.42.2",
                "proto": "tcp",
                "src": "10.0.42.1",
                "ttl": "64",
            },
            "tcp": {
                "dport": "http",
                "flags": "a",
            },
        },
    },
    # <- FIN
    {
        "common": {
            "task": {
                "comm": "socat",
            },
        },
        "kernel": {
            "probe_type": "raw_tracepoint",
            "symbol": "net:netif_rx",
        },
        "dev": {
            "name": "veth10",
        },
        "parsed_packet": {
            "ethernet": {
                "type": "ipv4",
            },
            "ip": {
                "dst": "10.0.42.2",
                "proto": "tcp",
                "src": "10.0.42.1",
                "ttl": "64",
            },
            "tcp": {
                "dport": "http",
                "flags": "fa",
            },
        },
    },
    # <- ACK
    {
        "kernel": {
            "probe_type": "raw_tracepoint",
            "symbol": "net:netif_rx",
        },
        "dev": {
            "name": "veth01",
        },
        "parsed_packet": {
            "ethernet": {
                "type": "ipv4",
            },
            "ip": {
                "dst": "10.0.42.1",
                "proto": "tcp",
                "src": "10.0.42.2",
                "ttl": "64",
            },
            "tcp": {
                "flags": "a",
                "sport": "http",
            },
        },
    },
]

assert_events_present("retis.data", expected_events)
EOF
	python test.py
}

skb_vlan() {
	two_ns_vlan

	# FIXME: stop using STDIN
	ip netns exec ns1 socat TCP-LISTEN:80 /dev/null &
	$retis collect -o -c skb,dev --skb-sections all \
		-f 'tcp port 80 or arp' -p net:net_dev_start_xmit \
		--cmd 'ip netns exec ns0 socat -T1 STDIN TCP:10.0.43.2:80; sleep 1'

	# FIXME: add support for packets coming back.
	cat >test.py <<EOF
from helpers import assert_events_present

expected_events = [
        # ARP req
        {
            "common": {
                "task": {
                    "comm": "socat",
                },
            },
            "kernel": {
                "probe_type": "raw_tracepoint",
                "symbol": "net:net_dev_start_xmit",
            },
            "dev": {
                "name": "veth01",
            },
            "skb": {
                "vlan_accel": {
                    "dei": False,
                    "pcp": 0,
                    "vid": 123,
                },
            },
            "parsed_packet": {
                "arp": {
                    "op": "who-has",
                    "psrc": "10.0.43.1",
                    "pdst": "10.0.43.2",
                },
                "ethernet": {
                    "type": "arp",
                },
            },
        },
        # ARP rep
        {
            "common": {
                "task": {
                    "comm": "socat",
                },
            },
            "kernel": {
                "probe_type": "raw_tracepoint",
                "symbol": "net:net_dev_start_xmit",
            },
            "dev": {
                "name": "veth10",
            },
            "parsed_packet": {
                "ethernet": {
                    "type": "n_802_1q",
                },
                "802.1q": {
                    "dei": "0",
                    "prio": "0",
                    "vlan": "123",
                    "type": "arp",
                },
            },
        },
        # SYN
        {
            "common": {
                "task": {
                    "comm": "socat",
                },
            },
            "kernel": {
                "probe_type": "raw_tracepoint",
                "symbol": "net:net_dev_start_xmit",
            },
            "dev": {
                "name": "veth01",
            },
            "skb": {
                "vlan_accel": {
                    "dei": False,
                    "pcp": 0,
                    "vid": 123,
                },
            },
            "parsed_packet": {
                "ethernet": {
                    "type": "ipv4",
                },
                "ip": {
                    "dst": "10.0.43.2",
                    "proto": "tcp",
                    "src": "10.0.43.1",
                    "ttl": "64",
                },
                "tcp": {
                    "dport": "http",
                    "flags": "s",
                },
            },
        },
        # SYN,ACK
        {
            "common": {
                "task": {
                    "comm": "socat",
                },
            },
            "kernel": {
                "probe_type": "raw_tracepoint",
                "symbol": "net:net_dev_start_xmit",
            },
            "dev": {
                "name": "veth10",
            },
            "parsed_packet": {
                "ethernet": {
                    "type": "n_802_1q",
                },
                "802.1q": {
                    "dei": "0",
                    "prio": "0",
                    "vlan": "123",
                    "type": "ipv4",
                },
            },
        },
]

assert_events_present("retis.data", expected_events)
EOF
	python test.py
}

run_tests skb_sanity skb_tcp_cc skb_vlan
