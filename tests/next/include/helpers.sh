#!/bin/bash

# Create two network namespaces, with a veth pair. Configuration is the
# following:
# ns0 - veth01 - 10.0.42.1/24 - 1111::1/64
# ns1 - veth10 - 10.0.42.2/24 - 1111::2/64
two_ns() {
	add_ns ns0 ns1
	add_veth_pair veth01 ns0 veth10 ns1
	ip -net ns0 address add 10.0.42.1/24 dev veth01
	ip -net ns1 address add 10.0.42.2/24 dev veth10
	ip -net ns0 address add 1111::1/64 dev veth01
	ip -net ns1 address add 1111::2/64 dev veth10
}

# On top of two_ns adds one VLAN interface per network namespace, as follow:
# ns0 - veth01.123 - 10.0.43.1/24 - 2222::1/64
# ns1 - veth10.123 - 10.0.43.2/24 - 2222::2/64 - VLAN h/w offload off
two_ns_vlan() {
	two_ns

	ip -net ns0 link add link veth01 name veth01.123 type vlan id 123
	ip -net ns1 link add link veth10 name veth10.123 type vlan id 123
	ip -net ns0 link set veth01.123 up
	ip -net ns1 link set veth10.123 up

	ip netns exec ns1 ethtool -K veth10 tx-vlan-offload off

	ip -net ns0 address add 10.0.43.1/24 dev veth01.123
	ip -net ns1 address add 10.0.43.2/24 dev veth10.123
	ip -net ns0 address add 2222::1/64 dev veth01.123
	ip -net ns1 address add 2222::2/64 dev veth10.123
}

# Create three network namespaces, with veth pairs. Configuration is the
# following:
# ns0 - veth01 - 10.0.42.1/24 - 1111::1/64
# ns1 - veth10 - 10.0.42.2/24 - 1111::2/64
# ns1 - veth12 - 10.0.43.1/24 - 2222::1/64
# ns2 - veth21 - 10.0.43.2/24 - 2222::2/64
#
# The correct routes are installed in ns0 and ns2. Forwarding is enabled on ns1.
three_ns() {
	two_ns

	add_ns ns2
	add_veth_pair veth12 ns1 veth21 ns2
	ip -net ns1 address add 10.0.43.1/24 dev veth12
	ip -net ns2 address add 10.0.43.2/24 dev veth21
	ip -net ns1 address add 2222::1/64 dev veth12
	ip -net ns2 address add 2222::2/64 dev veth21

	ip -net ns0 route add 10.0.43.0/24 via 10.0.42.2
	ip -net ns2 route add 10.0.42.0/24 via 10.0.43.1
	ip -net ns0 route add 2222::/64 via 1111::2
	ip -net ns2 route add 1111::/64 via 2222::1

	ip netns exec ns1 sysctl -w net.ipv4.conf.all.forwarding=1
	ip netns exec ns1 sysctl -w net.ipv6.conf.all.forwarding=1
}
