from testlib import Retis, assert_events_present


def test_meta_filter_string(two_ns_simple):
    ns = two_ns_simple
    retis = Retis()
    retis.collect(
        "-c",
        "skb",
        "-f",
        "icmp and host 10.0.42.2",
        "-m",
        "sk_buff.dev.name == 'veth01'",
        "-p",
        "tp:net:netif_rx",
    )
    print(ns.run("ns0", "ping", "-c", "1", "10.0.42.2"))
    retis.stop()

    expected_events = [
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
        }
    ]

    events = retis.events()
    assert_events_present(events, expected_events)


def test_meta_filter_number(two_ns_simple):
    ns = two_ns_simple

    # Retrieve inum value in the current namespace
    inum = int(
        ns.run("ns0", "readlink", "/proc/self/ns/net")
        .stdout.decode()
        .split(":")[1]
        .strip("[] \n")
    )

    retis = Retis()
    retis.collect(
        "-c",
        "skb",
        "-f",
        "icmp and host 10.0.42.2",
        "-m",
        "sk_buff.dev.nd_net.net.ns.inum == " + str(inum),
        "-p",
        "tp:net:netif_rx",
    )
    print(ns.run("ns0", "ping", "-c", "1", "10.0.42.2"))
    retis.stop()

    expected_events = [
        {
            "skb": {
                "dev": {
                    "name": "veth01",
                },
                "ip": {"v4": {}},
            }
        },
    ]

    events = retis.events()
    assert_events_present(events, expected_events)
