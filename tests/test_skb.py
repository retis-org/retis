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
        "skb",
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
            "skb": {
                "arp": {
                    "operation": "Request",
                    "spa": "10.0.42.1",
                    "tpa": "10.0.42.2",
                },
                "dev": {
                    "name": "veth10",
                },
                "eth": {
                    "etype": 2054,
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
            "skb": {
                "arp": {
                    "operation": "Reply",
                    "spa": "10.0.42.2",
                    "tpa": "10.0.42.1",
                },
                "dev": {
                    "name": "veth01",
                },
                "eth": {
                    "etype": 2054,
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
            "skb": {
                "dev": {
                    "name": "veth10",
                },
                "eth": {
                    "etype": 2048,
                },
                "ip": {
                    "daddr": "10.0.42.2",
                    "ecn": 0,
                    "protocol": 6,
                    "saddr": "10.0.42.1",
                    "ttl": 64,
                },
                "tcp": {
                    "dport": 80,
                    "flags": 2,
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
            "skb": {
                "dev": {
                    "name": "veth01",
                },
                "eth": {
                    "etype": 2048,
                },
                "ip": {
                    "daddr": "10.0.42.1",
                    "ecn": 0,
                    "protocol": 6,
                    "saddr": "10.0.42.2",
                    "ttl": 64,
                },
                "tcp": {
                    "flags": 18,
                    "sport": 80,
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
            "skb": {
                "dev": {
                    "name": "veth10",
                },
                "eth": {
                    "etype": 2048,
                },
                "ip": {
                    "daddr": "10.0.42.2",
                    "ecn": 0,
                    "protocol": 6,
                    "saddr": "10.0.42.1",
                    "ttl": 64,
                },
                "tcp": {
                    "dport": 80,
                    "flags": 16,
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
            "skb": {
                "dev": {
                    "name": "veth10",
                },
                "eth": {
                    "etype": 2048,
                },
                "ip": {
                    "daddr": "10.0.42.2",
                    "ecn": 0,
                    "protocol": 6,
                    "saddr": "10.0.42.1",
                    "ttl": 64,
                },
                "tcp": {
                    "dport": 80,
                    "flags": 17,
                },
            },
        },
        # -> ACK
        {
            "kernel": {
                "probe_type": "raw_tracepoint",
                "symbol": "net:netif_rx",
            },
            "skb": {
                "dev": {
                    "name": "veth01",
                },
                "eth": {
                    "etype": 2048,
                },
                "ip": {
                    "daddr": "10.0.42.1",
                    "ecn": 0,
                    "protocol": 6,
                    "saddr": "10.0.42.2",
                    "ttl": 64,
                },
                "tcp": {
                    "flags": 16,
                    "sport": 80,
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
            "skb": {
                "dev": {
                    "name": "veth01",
                },
                "eth": {
                    "etype": 2048,
                },
                "ip": {
                    "daddr": "10.0.42.1",
                    "ecn": 0,
                    "protocol": 6,
                    "saddr": "10.0.42.2",
                    "ttl": 64,
                },
                "tcp": {
                    "flags": 17,
                    "sport": 80,
                },
            },
        },
        # <- ACK
        {
            "kernel": {
                "probe_type": "raw_tracepoint",
                "symbol": "net:netif_rx",
            },
            "skb": {
                "dev": {
                    "name": "veth10",
                },
                "eth": {
                    "etype": 2048,
                },
                "ip": {
                    "daddr": "10.0.42.2",
                    "ecn": 0,
                    "protocol": 6,
                    "saddr": "10.0.42.1",
                    "ttl": 64,
                },
                "tcp": {
                    "dport": 80,
                    "flags": 16,
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
        "skb",
        "--skb-sections",
        "arp,dev,eth,vlan",
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
            "skb": {
                "arp": {
                    "operation": "Request",
                    "spa": "10.0.43.1",
                    "tpa": "10.0.43.2",
                },
                "dev": {
                    "name": "veth01",
                },
                "eth": {
                    "etype": 0x806,  # ARP
                },
                "vlan": {
                    "acceleration": True,
                    "dei": False,
                    "pcp": 0,
                    "vid": 123,
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
            "skb": {
                "dev": {
                    "name": "veth10",
                },
                "eth": {
                    "etype": 0x8100,  # 802.1Q
                },
                "vlan": {
                    "acceleration": False,
                    "dei": False,
                    "pcp": 0,
                    "vid": 123,
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
            "skb": {
                "dev": {
                    "name": "veth01",
                },
                "eth": {
                    "etype": 0x800,  # IP
                },
                "vlan": {
                    "acceleration": True,
                    "dei": False,
                    "pcp": 6,
                    "vid": 123,
                },
                "ip": {
                    "daddr": "10.0.43.2",
                    "ecn": 0,
                    "protocol": 6,
                    "saddr": "10.0.43.1",
                    "ttl": 64,
                },
                "tcp": {
                    "dport": 80,
                    "flags": 2,
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
            "skb": {
                "dev": {
                    "name": "veth10",
                },
                "eth": {
                    "etype": 0x8100,  # 802.1Q
                },
                "vlan": {
                    "acceleration": False,
                    "dei": False,
                    "pcp": 0,
                    "vid": 123,
                },
            },
        },
    ]
    events = retis.events()
    assert_events_present(events, expected_events)
