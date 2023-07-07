import pytest

from pyroute2 import IPRoute

from testlib import Retis


@pytest.fixture
def two_ports_skb(netns):
    '''Fixture that creates two netns connected through a veth pair.'''
    ipr = IPRoute()

    # Create netns & a veth pair
    ns0 = netns.add('ns0')
    ns1 = netns.add('ns1')
    ipr.link('add', ifname='veth01', peer='veth10', kind='veth')

    # Wait until links appear
    peer, veth = ipr.poll(
        ipr.link, 'dump', timeout=5, ifname=lambda x: x in ('veth01', 'veth10')
    )

    # Move ifaces to netns
    ipr.link('set', ifname='veth01', net_ns_fd='ns0')
    ipr.link('set', ifname='veth10', net_ns_fd='ns1')

    # Setup ifaces
    ns0.link('set', ifname='veth01', state='up')
    ns1.link('set', ifname='veth10', state='up')
    ns0.addr('add', index=ns0.link_lookup(ifname='veth01')[0], address='10.0.42.1', prefixlen=24)
    ns1.addr('add', index=ns1.link_lookup(ifname='veth10')[0], address='10.0.42.2', prefixlen=24)

    ipr.close()
    yield netns

def test_skb_sanity(two_ports_skb):
    ns = two_ports_skb
    retis = Retis()

    retis.collect("-c", "skb", "-f", "icmp", "-p", "kprobe:ip_rcv")
    print(ns.run("ns0", "ip", "link", "show"))
    print(ns.run("ns0", "ping", "-c", "1", "10.0.42.2"))
    retis.stop()

    events = retis.events()
    print(events)
    ip_rcv_events = list(
        filter(
            lambda e: e.get("kernel", {}).get("symbol") == "ip_rcv",
            events,
        )
    )

    assert len(ip_rcv_events) == 2
