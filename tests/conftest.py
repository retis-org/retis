# content of conftest.py

import pytest

from testlib import NetworkNamespaces, OVS
from pyroute2 import IPRoute


@pytest.fixture
def netns():
    """Fixture that provides a NetworkNamespaces handler and clears it after
    execution of the test."""
    nsman = NetworkNamespaces()
    yield nsman
    nsman.clear()


@pytest.fixture
def ovs():
    """Fixture that provides starts OVS, provides a OVS handler and stops it
    after execution of the test."""
    ovs = OVS()
    ovs.start()
    yield ovs
    ovs.stop()


def pytest_addoption(parser):
    parser.addoption(
        "--ovs-track",
        action="store_true",
        default=False,
        help="run ovs userspace tracking tests ",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--ovs-track"):
        # --ovs-track given in cli: do not skip slow tests
        return
    skip_ovs_track = pytest.mark.skip(reason="need --ovs-track option to run")
    for item in items:
        if "ovs_track" in item.keywords:
            item.add_marker(skip_ovs_track)


@pytest.fixture
def two_ports_skb(netns):
    """Fixture that creates two netns connected through a veth pair."""
    ipr = IPRoute()

    # Create netns & a veth pair
    ns0 = netns.add("ns0")
    ns1 = netns.add("ns1")
    ipr.link("add", ifname="veth01", peer="veth10", kind="veth")

    # Wait until links appear
    peer, veth = ipr.poll(
        ipr.link, "dump", timeout=5, ifname=lambda x: x in ("veth01", "veth10")
    )

    # Move ifaces to netns
    ipr.link("set", ifname="veth01", net_ns_fd="ns0")
    ipr.link("set", ifname="veth10", net_ns_fd="ns1")

    # Setup ifaces
    ns0.link("set", ifname="veth01", state="up")
    ns1.link("set", ifname="veth10", state="up")
    ns0.addr(
        "add",
        index=ns0.link_lookup(ifname="veth01")[0],
        address="10.0.42.1",
        prefixlen=24,
    )
    ns1.addr(
        "add",
        index=ns1.link_lookup(ifname="veth10")[0],
        address="10.0.42.2",
        prefixlen=24,
    )

    ipr.close()
    yield netns


@pytest.fixture
def two_port_ovs(ovs, netns):
    """Fixture that creates two netns connected together through OVS."""
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
