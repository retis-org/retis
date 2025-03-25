import time
import json
from io import BytesIO

from scapy.utils import PcapNgReader
import scapy.layers.l2
import scapy.layers.inet  # noqa: F401 (needed by packet.json())

from testlib import Retis, assert_events_present


def test_skb_tcp_cc_pcap(two_ns_simple):
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

    # Test `retis pcap --list-probes` first.
    assert retis.pcap("--list-probes") == b"raw_tracepoint:net:netif_rx\n"

    # Use `retis -p raw_tracepoint:net:netif_rx to create a pcapng and read it
    # with scapy (requires scapy 2.6.1). Then, compare it to list of expected events.
    packets_json = []
    packet_capture = retis.pcap("-p", "raw_tracepoint:net:netif_rx")
    with BytesIO(packet_capture) as io:
        packets = PcapNgReader(io).read_all()
        for packet in packets:
            packets_json.append(json.loads(packet.json()))

    expected_events = [
        # ARP req
        {
            "type": 2054,
            "payload": {
                "hwtype": 1,
                "ptype": 2048,
                "hwlen": 6,
                "plen": 4,
                "op": 1,
                "psrc": "10.0.42.1",
                "hwdst": "00:00:00:00:00:00",
                "pdst": "10.0.42.2",
            },
        },
        # ARP repl
        {
            "type": 2054,
            "payload": {
                "hwtype": 1,
                "ptype": 2048,
                "hwlen": 6,
                "plen": 4,
                "op": 2,
                "psrc": "10.0.42.2",
                "pdst": "10.0.42.1",
            },
        },
        # SYN
        {
            "type": 2048,
            "payload": {
                "version": 4,
                "proto": 6,
                "src": "10.0.42.1",
                "dst": "10.0.42.2",
                "payload": {
                    "dport": 80,
                    "flags": 2,
                },
            },
        },
        # SYN/ACK
        {
            "type": 2048,
            "payload": {
                "version": 4,
                "proto": 6,
                "src": "10.0.42.2",
                "dst": "10.0.42.1",
                "payload": {
                    "sport": 80,
                    "flags": 18,
                },
            },
        },
        # ACK
        {
            "type": 2048,
            "payload": {
                "version": 4,
                "proto": 6,
                "src": "10.0.42.1",
                "dst": "10.0.42.2",
                "payload": {
                    "dport": 80,
                    "flags": 16,
                },
            },
        },
        # -> FIN (+ ACK of previous segment)
        {
            "type": 2048,
            "payload": {
                "version": 4,
                "proto": 6,
                "src": "10.0.42.1",
                "dst": "10.0.42.2",
                "payload": {
                    "dport": 80,
                    "flags": 17,
                },
            },
        },
        # -> ACK
        {
            "type": 2048,
            "payload": {
                "version": 4,
                "proto": 6,
                "src": "10.0.42.2",
                "dst": "10.0.42.1",
                "payload": {
                    "sport": 80,
                    "flags": 16,
                },
            },
        },
        # <- FIN (+ ACK of previous segment)
        {
            "type": 2048,
            "payload": {
                "version": 4,
                "proto": 6,
                "src": "10.0.42.2",
                "dst": "10.0.42.1",
                "payload": {
                    "sport": 80,
                    "flags": 17,
                },
            },
        },
        # <- ACK
        {
            "type": 2048,
            "payload": {
                "version": 4,
                "proto": 6,
                "src": "10.0.42.1",
                "dst": "10.0.42.2",
                "payload": {
                    "dport": 80,
                    "flags": 16,
                },
            },
        },
    ]
    assert_events_present(packets_json, expected_events)
