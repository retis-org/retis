from testlib import Retis, assert_events_present


def test_drop_sanity(two_ns_simple):
    ns = two_ns_simple
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
    events = retis.events()
    assert_events_present(events, expected_events)
