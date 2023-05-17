import pytest
import time

from pyroute2 import IPRoute

from testlib import ovs, netns, Retis, assert_events_present


@pytest.fixture
def two_port_ovs(ovs, netns):
    """ Fixture that creates two netns connected together through OVS. """
    ipr = IPRoute()
    ovs.start()
    ovs.vsctl("add-br", "test")

    for idx in [0, 1]:
        local = f"p{idx}l"
        remote = f"p{idx}r"
        ns_name = f"ns{idx}"
        ip = f"192.168.1.{idx + 1}"

        # Create a netns
        ns = netns.add(ns_name)

        # Create a veth pair
        ipr.link("add", ifname=local, peer=remote, kind="veth")

        # Wait until links appear
        peer, veth = ipr.poll(
            ipr.link, "dump", timeout=5, ifname=lambda x: x in (local, remote)
        )
        # Set local side up and add it to ovs
        ipr.link("set", index=veth["index"], state="up")
        ovs.vsctl("add-port", "test", local)

        # Move peer to namespace, add an IP address to it and set it up
        ipr.link("set", index=peer["index"], net_ns_fd=ns_name)
        remote_iface = ns.link_lookup(ifname=remote)[0]
        ns.addr(
            "add",
            index=remote_iface,
            address=ip,
            prefixlen=24,
        )
        ns.link("set", index=remote_iface, state="up")

    ipr.close()

    yield (ovs, netns)

    # Cleanup
    ovs.vsctl("del-br", "test")

    # Delete veth links
    ipr = IPRoute()
    for idx in ["0", "1"]:
        local = "p{}l".format(idx)
        remote = "p{}r".format(idx)
        print(ipr.link_lookup(ifname=local))
        ipr.link("del", ifname=local)

    ipr.close()


def test_ovs_sanity(two_port_ovs):
    ns = two_port_ovs[1]

    retis = Retis()

    retis.collect("-c", "ovs,skb", "-f", "icmp")
    print(ns.run("ns0", "ip", "link", "show"))
    print(ns.run("ns0", "ping", "-c", "1", "192.168.1.2"))
    retis.stop()

    events = retis.events()
    print(events)
    execs = list(filter(lambda e: e.get("kernel", {}).get("symbol") == "openvswitch:ovs_do_execute_action",
                      events))

    assert len(execs) == 2

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
            "skb-tracking": {
                "orig_head": "&orig_head"  # Store orig_head in aliases
            },
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
            "skb-tracking": {
                "orig_head": "*orig_head"  # Check same orig_head
            },
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
            "skb-tracking": {
                "orig_head": "*orig_head"  # Check same orig_head
            },
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
        # Packet is received by kernel. Action execution starts.
        {
            "kernel": {
                "probe_type": "kprobe",
                "symbol": "ovs_execute_actions",
            },
            "skb": skb,
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
        # OVS kernel action execution ends.
        {
            "kernel": {
                "probe_type": "kretprobe",
                "symbol": "ovs_execute_actions",
            },
            "skb": skb,
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
    time.sleep(5)
    ns.run("ns0", "ping", "-c", "1", "192.168.1.2")
    retis.stop()

    events = retis.events()

    skb_icmp_req = {
        "saddr": "192.168.1.1",
        "daddr": "192.168.1.2",
        "icmp_type": 8,  # Echo Request
    }
    skb_icmp_resp = {
        "saddr": "192.168.1.2",
        "daddr": "192.168.1.1",
        "icmp_type": 0,  # Echo Reply
    }

    # Expected eventes for both directions
    expected_events = gen_expected_events(skb_icmp_req) + gen_expected_events(
        skb_icmp_resp
    )

    assert_events_present(events, expected_events)

@pytest.mark.ovs_track
def test_ovs_tracking_filtered(two_port_ovs):
    (ovs, ns) = two_port_ovs

    retis = Retis()

    # Clean stale flows if any
    ovs.appctl("dpctl/del-flows")

    # Not warming up ARP here so we expect some ARP traffic to flow but it
    # should be filtered out
    # Start collection and test
    retis.collect("-c", "ovs,skb,skb-tracking",
                  "-f", "ip src 192.168.1.1 and icmp",
                  "--skb-sections", "l2,l3,icmp",
                  "--ovs-track")
    time.sleep(7)
    ns.run("ns0", "ping", "-c", "1", "192.168.1.2")
    retis.stop()

    events = retis.events()

    skb_icmp_req = {
        "saddr": "192.168.1.1",
        "daddr": "192.168.1.2",
        "icmp_type": 8,  # Echo Request
    }

    # We only expect one way events
    expected_events = gen_expected_events(skb_icmp_req)
    assert_events_present(events, expected_events)

    # Ensure we didn't pick up any ARP or return traffic
    return_events = filter(
        lambda e: e.get("skb", {}).get("saddr", None) == "192.168.1.2",
        events)
    assert len(list(return_events)) == 0

    arps = filter(
        lambda e: e.get("skb", {}).get("etype", None) == 0x0806,
        events)
    assert len(list(arps)) == 0
