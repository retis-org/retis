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
