from testlib import Retis, assert_events_present


def test_meta_filter(two_ns_simple):
    ns = two_ns_simple
    retis = Retis()
    retis.collect(
        "-c", "skb", "-m", "sk_buff.dev.name == 'veth01'", "-p", "tp:net:netif_rx"
    )
    print(ns.run("ns0", "ping", "-c", "1", "10.0.42.2"))
    retis.stop()

    expected_events = [
        {
            "skb": {
                "dev": {
                    "name": "veth01",
                },
                "ip": {"v6": {}},
            },
        },
        {
            "skb": {
                "dev": {
                    "name": "veth01",
                },
                "arp": {
                    "spa": "10.0.42.2",
                    "tpa": "10.0.42.1",
                },
            },
        },
        {
            "skb": {
                "dev": {
                    "name": "veth01",
                },
                "ip": {
                    "saddr": "10.0.42.2",
                    "daddr": "10.0.42.1",
                },
                "icmp": {
                    "type": 0,
                    "code": 0,
                },
            },
        },
    ]

    events = retis.events()
    assert_events_present(events, expected_events)
