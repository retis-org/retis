import time

from testlib import Retis, assert_events_present


def test_skb_sanity(two_ns_simple):
    ns = two_ns_simple
    retis = Retis()

    retis.collect("-c", "skb", "-f", "icmp", "-p", "kprobe:ip_rcv")
    print(ns.run("ns0", "ip", "link", "show"))
    print(ns.run("ns0", "ping", "-c", "1", "10.0.42.2"))
    retis.stop()

    events = retis.events()
    print(events)
    ip_rcv_events = list(
        filter(
            lambda e: e.get("kernel", {}).get("symbol") == "ip_rcv",
            events,
        )
    )

    assert len(ip_rcv_events) == 2


def test_skb_tcp_cc(two_ns_simple):
    ns = two_ns_simple
    retis = Retis()

    retis.collect(
        "-c",
        "skb,dev",
        "--skb-sections",
        "all",
        "-f",
        "tcp port 80 or arp",
        "-p",
        "tp:net:netif_rx",
    )
    print(ns.run_bg("ns1", "socat", "TCP-LISTEN:80", "STDOUT"))
    time.sleep(1)
    print(ns.run("ns0", "socat", "-T", "1", "-", "TCP:10.0.42.2:80"))
    retis.stop()

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
        # -> ACK
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
        # <- ACK
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
    ]
    events = retis.events()
    assert_events_present(events, expected_events)


def test_skb_vlan(two_ns_vlan):
    ns = two_ns_vlan
    retis = Retis()

    retis.collect(
        "-c",
        "skb,dev",
        "--skb-sections",
        "all",
        "-f",
        "tcp port 80 or arp",
        "-p",
        "net:net_dev_start_xmit",
    )
    print(ns.run_bg("ns1", "socat", "TCP-LISTEN:80", "STDOUT"))
    print(ns.run("ns0", "socat", "-T", "1", "-", "TCP:10.0.43.2:80"))
    retis.stop()

    # A known limitation for now in Retis: it does not support VLAN nor tunnels
    # for parsing the inner payload right at the moment. Therefore, for the
    # return packets which are not offloaded, do not verify ARP or TCP.
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
                    "pcp": 6,
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
    events = retis.events()
    assert_events_present(events, expected_events)
