from testlib import Retis, assert_events_present


def test_drop_sanity(two_ports_skb):
    ns = two_ports_skb
    retis = Retis()

    retis.collect("-c", "skb-drop,skb", "-f", "tcp")
    print(ns.run_fail("ns0", "socat", "-T", "1", "-", "TCP:10.0.42.2:443"))
    retis.stop()

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
            "skb": {
                "dev": {
                    "name": "veth10",
                },
                "ip": {
                    "daddr": "10.0.42.2",
                    "ecn": 0,
                    "protocol": 6,
                    "saddr": "10.0.42.1",
                    "ttl": 64,
                },
                "tcp": {
                    "dport": 443,
                    "flags": 2,
                },
            },
            "skb-drop": {
                "drop_reason": "NO_SOCKET",
            },
        },
    ]
    events = retis.events()
    assert_events_present(events, expected_events)
