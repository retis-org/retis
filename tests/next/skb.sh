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

skb_l2_l3() {
	two_ns

	# The ARP request will generate a packet event with a fake Ethernet
	# header.
	ip -net ns0 neigh flush all
	$retis collect -o \
		-p arp_xmit \
		--cmd "ip netns exec ns0 ping -c1 10.0.42.2; sleep 1"
	$retis print -e |\
		grep -E "^  request who-has 10.0.42.2 tell 10.0.42.1"
	$retis pcap -p arp_xmit | tcpdump -ennr - |\
		grep -E "f0:c4:cc:14:00:00 > f0:c4:cc:14:00:00, ethertype ARP \(0x0806\), .* Request who-has 10.0.42.2 tell 10.0.42.1"

	# Start the server for the next tests.
	ip netns exec ns1 socat TCP-LISTEN:80 /dev/null &

	# Collecting on ip_output will collect L3-only packets while the ip_rcv
	# probe will collect L2 packets.
	$retis collect -o \
		-f "tcp port 80 or arp" \
		-p ip_output -p ip_rcv \
		--cmd "ip netns exec ns0 socat - TCP:10.0.42.2:80"

	# Check the ip_output handling (with -e).
	head -1 retis.data > ip_output.data
	grep \"ip_output\" retis.data >> ip_output.data
	$retis print -e ip_output.data |\
		grep -E "^  10.0.42.1.[0-9]{4,5} > 10.0.42.2.80 .* proto TCP \(6\) flags \[S\]"

	# Check the ip_rcv handling (with -e).
	head -1 retis.data > ip_rcv.data
	grep \"ip_rcv\" retis.data >> ip_rcv.data
	$retis print -e ip_rcv.data |\
		grep -E "^  ([0-9a-f]{2}:?){6} > ([0-9a-f]{2}:?){6} ethertype IPv4 \(0x0800\) 10.0.42.1.[0-9]{4,5} > 10.0.42.2.80 .* proto TCP \(6\) flags \[S\]"

	# Check PCAP content from ip_output.
	$retis pcap -p ip_output | tcpdump -nnr - |\
		grep -E "IP 10.0.42.1.[0-9]{4,5} > 10.0.42.2.80: Flags \[S\]"

	# Check PCAP content from ip_rcv.
	$retis pcap -p ip_rcv | tcpdump -nnr - |\
		grep -E "IP 10.0.42.1.[0-9]{4,5} > 10.0.42.2.80: Flags \[S\]"
}

run_tests skb_sanity skb_tcp_cc skb_vlan skb_l2_l3
