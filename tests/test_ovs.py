import copy
import time

import pytest

from testlib import Retis, assert_events_present, kernel_version_lt


def test_ovs_sanity(two_port_ovs):
    ns = two_port_ovs[1]

    retis = Retis()

    retis.collect("-c", "ovs,skb", "-f", "icmp")
    print(ns.run("ns0", "ip", "link", "show"))
    print(ns.run("ns0", "ping", "-c", "1", "192.168.1.2"))
    retis.stop()

    events = retis.events()
    print(events)
    execs = list(
        filter(
            lambda e: e.get("kernel", {}).get("symbol")
            == "openvswitch:ovs_do_execute_action",
            events,
        )
    )

    assert len(execs) == 2


# Test OVS and conntrack integration
def test_ovs_conntrack(two_port_ovs):
    ovs, ns = two_port_ovs

    # Configure a simple conntrack set of flows
    ovs.ofctl("del-flows", "test")
    # Allow ARP
    ovs.ofctl("add-flow", "test", "table=0,arp actions=NORMAL")
    # Send untracked traffic through ct
    ovs.ofctl(
        "add-flow", "test", "table=0,ct_state=-trk,ip actions=ct(table=1,zone=43210)"
    )
    # Commit new connections
    ovs.ofctl(
        "add-flow",
        "test",
        "table=1,ct_state=+trk+new,ip actions=ct(zone=43210,commit),NORMAL",
    )
    # Accept established connection
    ovs.ofctl("add-flow", "test", "table=1,ct_state=+trk+est,ip actions=NORMAL")

    retis = Retis()
    retis.collect(
        "-c",
        "skb,ovs,ct",
        "--skb-sections",
        "all",
        "-f",
        "host 192.168.1.1 and (tcp port 80 or arp)",
    )
    print(ns.run_bg("ns1", "socat", "TCP-LISTEN:80", "STDOUT"))
    time.sleep(1)
    print(ns.run("ns0", "socat", "-T", "3", "-,ignoreeof", "TCP:192.168.1.2:80"))
    retis.stop()

    events = retis.events()

    # Expected events
    ovs_exec = {
        "probe_type": "raw_tracepoint",
        "symbol": "openvswitch:ovs_do_execute_action",
    }
    orig_skb = {
        "eth": {
            "etype": 2048,
        },
        "ip": {
            "daddr": "192.168.1.2",
            "saddr": "192.168.1.1",
            "ttl": 64,
        },
        "tcp": {
            "dport": 80,
        },
    }
    reply_skb = {
        "eth": {
            "etype": 2048,
        },
        "ip": {
            "daddr": "192.168.1.1",
            "saddr": "192.168.1.2",
            "ttl": 64,
        },
        "tcp": {
            "sport": 80,
        },
    }

    # SYN
    syn = copy.deepcopy(orig_skb)
    syn["tcp"]["flags"] = 2

    # SYN+ACK
    syn_ack = copy.deepcopy(reply_skb)
    syn_ack["tcp"]["flags"] = 18

    # ACK
    ack = copy.deepcopy(orig_skb)
    ack["tcp"]["flags"] = 16

    # FIN
    fin = copy.deepcopy(syn)
    fin["tcp"]["flags"] = 17

    expected_events = [
        # SYN actions: ct, recirc, ct(commit), output
        {
            "kernel": ovs_exec,
            "skb": syn,
            "ovs": {"action": "ct", "flags": 4, "zone_id": 43210},
        },
        {
            "kernel": ovs_exec,
            "skb": syn,
            "ovs": {
                "action": "recirc",
            },
            "ct": {"state": "new", "zone_id": 43210},
        },
        {
            "kernel": ovs_exec,
            "skb": syn,
            "ovs": {
                "action": "ct",
                "flags": 5,
                "zone_id": 43210,
            },
        },
        {
            "kernel": ovs_exec,
            "skb": syn,
            "ovs": {"action": "output"},
            "ct": {"state": "new", "zone_id": 43210},
        },
        # SYN+ACK actions: ct, recirc, output
        {
            "kernel": ovs_exec,
            "skb": syn_ack,
            "ovs": {"action": "ct", "flags": 4, "zone_id": 43210},
        },
        {
            "kernel": ovs_exec,
            "skb": syn_ack,
            "ovs": {
                "action": "recirc",
            },
            "ct": {"state": "reply", "zone_id": 43210},
        },
        {
            "kernel": ovs_exec,
            "skb": syn_ack,
            "ovs": {
                "action": "output",
            },
        },
        # ACK actions: ct, recirc, output
        {
            "kernel": ovs_exec,
            "skb": ack,
            "ovs": {"action": "ct", "flags": 4, "zone_id": 43210},
        },
        {
            "kernel": ovs_exec,
            "skb": ack,
            "ovs": {
                "action": "recirc",
            },
            "ct": {"state": "established", "zone_id": 43210},
        },
        {
            "kernel": ovs_exec,
            "skb": ack,
            "ovs": {
                "action": "output",
            },
        },
        # FIN actions: ct, recirc, output
        {
            "kernel": ovs_exec,
            "skb": fin,
            "ovs": {"action": "ct", "flags": 4, "zone_id": 43210},
        },
        {
            "kernel": ovs_exec,
            "skb": fin,
            "ovs": {
                "action": "recirc",
                "id": "&recirc_id_orig",  # Store orig recirc_id
            },
            "ct": {"state": "established", "zone_id": 43210},
        },
        {
            "kernel": ovs_exec,
            "skb": fin,
            "ovs": {
                "action": "output",
                "recirc_id": "*recirc_id_orig",  # Check orig recirc_id
            },
            "ct": {"state": "established", "zone_id": 43210},
        },
        # ACK actions: ct, recirc, output
        {
            "kernel": ovs_exec,
            "skb": ack,
            "ovs": {"action": "ct", "flags": 4, "zone_id": 43210},
        },
        {
            "kernel": ovs_exec,
            "skb": ack,
            "ovs": {
                "action": "recirc",
                "id": "&recirc_id_reply",  # Store reply recirc_id
            },
            "ct": {"state": "established", "zone_id": 43210},
        },
        {
            "kernel": ovs_exec,
            "skb": ack,
            "ovs": {
                "action": "output",
                "recirc_id": "*recirc_id_reply",  # Check reply recirc_id
            },
            "ct": {"state": "established", "zone_id": 43210},
        },
    ]

    # Only interested in TCP OVS execute actions.
    def interested(e):
        return (
            "kernel" in e
            and e["kernel"]["symbol"] == "openvswitch:ovs_do_execute_action"
            and "skb" in e
            and e["skb"].get("ip")
        )

    events = list(filter(interested, events))
    assert_events_present(events, expected_events)


# Expected OVS upcall events.
def gen_expected_events(skb):
    return [
        # Packet hits ovs_dp_upcall. Upcall start.
        {
            "kernel": {
                "probe_type": "raw_tracepoint",
                "symbol": "openvswitch:ovs_dp_upcall",
            },
            "ovs": {"event_type": "upcall"},
            "skb": skb,
            "skb-tracking": {"orig_head": "&orig_head"},  # Store orig_head in aliases
        },
        # Packet is enqueued for upcall (only 1, i.e: no fragmentation
        # expected).
        {
            "kernel": {
                "probe_type": "kretprobe",
                "symbol": "queue_userspace_packet",
            },
            "ovs": {
                "event_type": "upcall_enqueue",
                "queue_id": "&queue_id",  # Store queue_id
            },
            "skb": skb,
            "skb-tracking": {"orig_head": "*orig_head"},  # Check same orig_head
        },
        # Upcall ends.
        {
            "kernel": {
                "probe_type": "kretprobe",
                "symbol": "ovs_dp_upcall",
            },
            "ovs": {
                "event_type": "upcall_return",
            },
            "skb": skb,
            "skb-tracking": {"orig_head": "*orig_head"},  # Check same orig_head
        },
        # Upcall is received by userspace.
        {
            "userspace": {
                "probe_type": "usdt",
                "symbol": "dpif_recv:recv_upcall",
            },
            "ovs": {
                "event_type": "recv_upcall",
                "queue_id": "*queue_id",  # Check queue_id
            },
        },
        # ovs-vswitchd puts a new flow for this packet.
        {
            "userspace": {
                "probe_type": "usdt",
                "symbol": "dpif_netlink_operate__:op_flow_put",
            },
            "ovs": {
                "event_type": "flow_operation",
                "op_type": "put",
                "queue_id": "*queue_id",  # Check queue_id
            },
        },
        # ovs-vswitchd executes the actions on this packet.
        {
            "userspace": {
                "probe_type": "usdt",
                "symbol": "dpif_netlink_operate__:op_flow_execute",
            },
            "ovs": {
                "event_type": "flow_operation",
                "op_type": "exec",
                "queue_id": "*queue_id",  # Check queue_id
            },
        },
        # Single action execution: Output.
        {
            "kernel": {
                "probe_type": "raw_tracepoint",
                "symbol": "openvswitch:ovs_do_execute_action",
            },
            "skb": skb,
            "ovs": {
                "action": "output",
                "event_type": "action_execute",
                "queue_id": "*queue_id",  # Check queue_id
            },
        },
    ]


@pytest.mark.ovs_track
def test_ovs_tracking(two_port_ovs):
    (ovs, ns) = two_port_ovs

    retis = Retis()

    # Clean stale flows if any
    ovs.appctl("dpctl/del-flows")

    # Ensure ARP tables are warm
    ns.run("ns0", "arping", "-c", "1", "192.168.1.2")

    # Start collection and test
    retis.collect("-c", "ovs,skb,skb-tracking", "-f", "ip", "--ovs-track")
    ns.run("ns0", "ping", "-c", "1", "192.168.1.2")
    retis.stop()

    events = retis.events()

    skb_icmp_req = {
        "ip": {
            "saddr": "192.168.1.1",
            "daddr": "192.168.1.2",
        },
        "icmp": {"type": 8},  # Echo Request
    }
    skb_icmp_resp = {
        "ip": {
            "saddr": "192.168.1.2",
            "daddr": "192.168.1.1",
        },
        "icmp": {"type": 0},  # Echo Reply
    }

    # Expected eventes for both directions
    expected_events = gen_expected_events(skb_icmp_req) + gen_expected_events(
        skb_icmp_resp
    )

    assert_events_present(events, expected_events)

    series = retis.sort()
    # All events from the same direction must belong to the same packet (same
    # global tracking id).
    # 2 series + the initial md.
    assert len(series) == 3
    assert len(series[1]) == len(expected_events) / 2
    assert len(series[2]) == len(expected_events) / 2


@pytest.mark.ovs_track
def test_ovs_tracking_filtered(two_port_ovs):
    (ovs, ns) = two_port_ovs

    retis = Retis()

    # Clean stale flows if any
    ovs.appctl("dpctl/del-flows")

    # Not warming up ARP here so we expect some ARP traffic to flow but it
    # should be filtered out.
    retis.collect(
        "-c",
        "ovs,skb,skb-tracking",
        "-f",
        "ip src 192.168.1.1 and icmp",
        "--skb-sections",
        "eth,ip,icmp",
        "--ovs-track",
    )
    ns.run("ns0", "ping", "-c", "1", "192.168.1.2")
    retis.stop()

    events = retis.events()

    skb_icmp_req = {
        "ip": {
            "saddr": "192.168.1.1",
            "daddr": "192.168.1.2",
        },
        "icmp": {"type": 8},  # Echo Request
    }

    # We only expect one way events
    expected_events = gen_expected_events(skb_icmp_req)
    assert_events_present(events, expected_events)

    # Ensure we didn't pick up any ARP or return traffic
    return_events = filter(
        lambda e: e.get("skb", {}).get("ip", {}).get("saddr", None) == "192.168.1.2",
        events,
    )
    assert len(list(return_events)) == 0

    arps = filter(
        lambda e: e.get("skb", {}).get("eth", {}).get("etype", None) == 0x0806,
        events,
    )
    assert len(list(arps)) == 0


@pytest.mark.ovs_track
def test_ovs_filtered_userspace(two_port_ovs):
    (ovs, ns) = two_port_ovs

    retis = Retis()

    # Clean stale flows if any
    ovs.appctl("dpctl/del-flows")

    # Setting a filter that should not match any traffic.
    retis.collect(
        "-c",
        "ovs,skb,skb-tracking",
        "-f",
        "udp port 9999",
        "--ovs-track",
    )
    ns.run("ns0", "ping", "-c", "1", "192.168.1.2")
    retis.stop()

    events = retis.events()

    # Ensure we didn't pick up userspace events, i.e: all got filtered out.
    userspace = filter(lambda e: "userspace" in e, events)
    assert len(list(userspace)) == 0


@pytest.mark.skipif(
    kernel_version_lt("6.6"), reason="Kernel does not support OVS drop action"
)
def test_ovs_drop(two_port_ovs):
    ovs, ns = two_port_ovs

    ovs_ver = ovs.version()
    if ovs_ver[0] < 3 or (ovs_ver[0] == 3 and ovs_ver[1] < 4):
        pytest.skip(
            "OVS version does not support explicit drop actions (introduced in 3.4)"
        )

    ovs.ofctl("del-flows", "test")
    # Allow ARP
    ovs.ofctl("add-flow", "test", "table=0,arp actions=NORMAL")
    # Drop IP
    ovs.ofctl("add-flow", "test", "table=0,ip actions=drop")

    retis = Retis()

    retis.collect("-c", "ovs,skb", "-f", "icmp")
    ns.run_fail("ns0", "ping", "-w", "1", "-4", "-c", "1", "192.168.1.2")
    retis.stop()

    events = retis.events()
    print(events)

    def is_drops(reason):
        def is_drops_reason(e):
            return (
                e.get("kernel", {}).get("symbol") == "openvswitch:ovs_do_execute_action"
                and e.get("ovs", {}).get("action") == "drop"
                and e.get("ovs", {}).get("reason") == reason
            )

        return is_drops_reason

    drops = list(filter(is_drops(0), events))
    assert len(drops) == 1

    ovs.ofctl("del-flows", "test")
    # Allow ARP
    ovs.ofctl("add-flow", "test", "table=0,arp actions=NORMAL")
    # Create loop
    ovs.ofctl("add-flow", "test", "table=0,ip actions=resubmit(,1)")
    ovs.ofctl("add-flow", "test", "table=1,ip actions=resubmit(,0)")

    retis = Retis()

    retis.collect("-c", "ovs,skb", "-f", "icmp")
    ns.run_fail("ns0", "ping", "-w", "1", "-4", "-c", "1", "192.168.1.2")
    retis.stop()

    events = retis.events()
    print(events)

    # Should report XLATE_RECURSION_TOO_DEEP (2)
    drops = list(filter(is_drops(2), events))
    assert len(drops) == 1


def test_ovs_detrace_sanity(two_port_ovs):
    """Tests that identical flows are not enriched more than once."""
    ovs, ns = two_port_ovs

    retis = Retis()

    retis.collect("-c", "ovs,skb", "--ovs-enrich-flows", "-f", "icmp")

    print(ns.run("ns0", "ping", "-4", "-i", "0.1", "-c", "10", "192.168.1.2"))

    retis.stop()

    events = retis.events()
    print(events)

    lookups = list(
        filter(
            lambda e: e.get("ovs", {}).get("event_type", None) == "flow_lookup",
            events,
        )
    )

    enrich = list(
        filter(
            lambda e: e.get("ovs-detrace", None),
            events,
        )
    )

    assert len(lookups) == 18
    assert len(enrich) == 2

    ovs_ver = ovs.version()
    if ovs_ver[0] < 3 or (ovs_ver[0] == 3 and ovs_ver[1] < 4):
        return  # OVS version does not support ofproto/detrace command

    for e in enrich:
        assert len(e["ovs-detrace"].get("ofpflows", [])) > 0


def test_ovs_detrace_throtle(two_port_ovs):
    """Tests that OVS is not queried more than expected."""
    ovs, ns = two_port_ovs

    # Configure a simple conntrack set of flows
    ovs.ofctl("del-flows", "test")
    # Allow ARP
    ovs.ofctl("add-flow", "test", "table=0,arp actions=NORMAL")
    # Send untracked traffic through ct using the destination port as zone.
    # This will force a different flow per connection
    ovs.ofctl(
        "add-flow",
        "test",
        "table=0,in_port=p0l,ct_state=-trk,tcp"
        "actions=move:NXM_OF_TCP_SRC[]->NXM_NX_REG0[0..15],ct(table=1,zone=NXM_NX_REG0[0..15])",  # noqa: 501
    )
    ovs.ofctl(
        "add-flow",
        "test",
        "table=0,in_port=p1l,ct_state=-trk,tcp"
        "actions=move:NXM_OF_TCP_DST[]->NXM_NX_REG0[0..15],ct(table=1,zone=NXM_NX_REG0[0..15])",  # noqa: 501
    )
    # Commit new connections
    ovs.ofctl(
        "add-flow",
        "test",
        "table=1,ct_state=+new+trk,tcp,in_port=p0l"
        "actions=move:NXM_OF_TCP_SRC[]->NXM_NX_REG0[0..15],ct(commit,zone=NXM_NX_REG0[0..15]),NORMAL",  # noqa: 501
    )
    ovs.ofctl(
        "add-flow",
        "test",
        "table=1,ct_state=+new+trk,tcp,in_port=p1l"
        "actions=move:NXM_OF_TCP_DST[]->NXM_NX_REG0[0..15],ct(commit,zone=NXM_NX_REG0[0..15]),NORMAL",  # noqa: 501
    )

    # Accept established connection
    ovs.ofctl("add-flow", "test", "table=1,ct_state=+trk+est,ip actions=NORMAL")

    retis = Retis()

    retis.collect(
        "-c", "ovs,skb", "--ovs-enrich-flows", "-f", "tcp and host 192.168.1.1"
    )

    server = ns.run_bg("ns1", "socat", "TCP-LISTEN:9999,fork", "STDOUT")
    time.sleep(1)

    # Send 100 requests
    print(
        ns.run(
            "ns0",
            "/bin/sh",
            "-c",
            "for port in `seq 1 100`; do "
            "echo hello | "
            "socat -t 0 - TCP:192.168.1.2:9999;"
            "done",
        )
    )

    retis.stop()
    server.kill()

    events = retis.events()

    lookups = list(
        filter(
            lambda e: e.get("ovs", {}).get("event_type", None) == "flow_lookup",
            events,
        )
    )

    enrich = list(
        filter(
            lambda e: e.get("ovs-detrace", None),
            events,
        )
    )

    # There are 7 flow lookups per connection
    assert len(lookups) >= 700

    MIN_DELAY = 50 * 1000000  # 50ms
    last = None
    for e in enrich:
        print(e)
        current = e["common"]["timestamp"]
        if not last:
            last = current
            continue

        delta = current - last
        # Delta should be around 100ms but some inaccuracy can exist
        # because time between events is not exactly the same as time between
        # unixctl calls. Allow for a 10% deviation.
        print(delta)
        assert (MIN_DELAY - delta) / MIN_DELAY <= 0.1
