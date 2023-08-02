import time

from testlib import Retis, assert_events_present


def test_skb_sanity(two_ports_skb):
    ns = two_ports_skb
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


def test_skb_tcp_cc(two_ports_skb):
    ns = two_ports_skb
    retis = Retis()

    retis.collect(
        "-c",
        "skb",
        "--skb-sections",
        "all",
        "-f",
        "tcp port 80",
        "-p",
        "tp:net:netif_rx",
    )
    print(ns.run_bg("ns1", "socat", "TCP-LISTEN:80", "STDOUT"))
    time.sleep(1)
    print(ns.run("ns0", "socat", "-T", "1", "-", "TCP:10.0.42.2:80"))
    retis.stop()

    expected_events = [
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
