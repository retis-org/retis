from testlib import Retis, assert_events_present


def test_tracking_sanity(three_ns_nat):
    ns = three_ns_nat
    retis = Retis()

    retis.collect(
        "-c",
        "skb,skb-tracking",
        "-f",
        "icmp and host 10.0.255.1",
        "-p",
        "tp:net:netif_rx",
    )
    print(ns.run("ns0", "ping", "-c", "1", "10.0.255.1"))
    retis.stop()

    expected_events = [
        {
            "skb": {
                "dev": {
                    "name": "veth10",
                },
            },
            "parsed_packet": {
                "icmp": {
                    "code": "0",
                    "type": "echo-request",
                },
                "ip": {
                    "src": "10.0.42.2",
                    "dst": "10.0.255.1",
                },
            },
            "skb-tracking": {
                "orig_head": "&orig_head",
                "timestamp": "&timestamp",
                "skb": "&skb",
            },
        },
        {
            "skb": {
                "dev": {
                    "name": "veth21",
                },
            },
            "parsed_packet": {
                "icmp": {
                    "code": "0",
                    "type": "echo-request",
                },
                "ip": {
                    "src": "10.0.42.2",
                    "dst": "10.0.43.2",
                },
            },
            "skb-tracking": {
                "orig_head": "*orig_head",
                "timestamp": "*timestamp",
                "skb": "*skb",
            },
        },
        {
            "skb": {
                "dev": {
                    "name": "veth01",
                },
            },
            "parsed_packet": {
                "icmp": {
                    "code": "0",
                    "type": "echo-reply",
                },
                "ip": {
                    "src": "10.0.255.1",
                    "dst": "10.0.42.2",
                },
            },
            "skb-tracking": {
                "orig_head": "!orig_head",
                "timestamp": "!timestamp",
            },
        },
    ]

    events = retis.events()
    assert_events_present(events, expected_events)
