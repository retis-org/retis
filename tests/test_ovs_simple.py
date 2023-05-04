import pytest
from pyroute2 import IPRoute

from testlib import ovs, netns, Retis


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


def test_ovs_simple(two_port_ovs):
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
