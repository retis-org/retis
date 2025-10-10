#!/bin/bash

# Create two network namespaces, with a veth pair. Configuration is the
# following:
# ns0 - veth01 - 10.0.42.1/24 - 1111::1/64
# ns1 - veth10 - 10.0.42.2/24 - 1111::2/64
two_ns_simple() {
	add_ns ns0 ns1
	add_veth_pair veth01 ns0 veth10 ns1
	ip -net ns0 address add 10.0.42.1/24 dev veth01
	ip -net ns1 address add 10.0.42.2/24 dev veth10
	ip -net ns0 address add 1111::1/64 dev veth01
	ip -net ns1 address add 1111::2/64 dev veth10
}

# On top of two_ns_simple adds one VLAN interface per network namespace, as
# follow:
# ns0 - veth01.123 - 10.0.43.1/24 - 2222::1/64
# ns1 - veth10.123 - 10.0.43.2/24 - 2222::2/64 - VLAN h/w offload off
two_ns_vlan_simple() {
	two_ns_simple

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
