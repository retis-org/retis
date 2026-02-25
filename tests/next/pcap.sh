#!/bin/bash
source $(dirname $0)/include/lib.sh
source $(dirname $0)/include/helpers.sh

pcap_tcp_cc() {
	two_ns

	ip netns exec ns1 socat TCP-LISTEN:80 /dev/null &
	$retis collect -o \
		-f "tcp port 80 or arp" \
		-p net:netif_rx -p net:net_dev_start_xmit \
		--cmd "ip netns exec ns0 socat - TCP:10.0.42.2:80"

	$retis pcap -p tp:net:netif_rx -o retis.pcap

        $retis stats > stats
        grep -q "Number of events: 18" stats
        grep -q "raw_tracepoint/net:netif_rx: 9" stats
        grep -q "raw_tracepoint/net:net_dev_start_xmit: 9" stats

	# Check PCAP content.
	[ $(tcpdump -nnr retis.pcap | wc -l) == 9 ]
	tcpdump -nnr retis.pcap | grep "ARP, Request who-has 10.0.42.2 tell 10.0.42.1"
	tcpdump -nnr retis.pcap | grep "ARP, Reply 10.0.42.2 is-at"
	tcpdump -nnr retis.pcap | grep -E "IP 10.0.42.1.[0-9]{4,5} > 10.0.42.2.80: Flags \[S\]"
	tcpdump -nnr retis.pcap | grep -E "IP 10.0.42.2.80 > 10.0.42.1.[0-9]{4,5}: Flags \[S.\]"
	tcpdump -nnr retis.pcap | grep -E "IP 10.0.42.1.[0-9]{4,5} > 10.0.42.2.80: Flags \[.\]"
	tcpdump -nnr retis.pcap | grep -E "IP 10.0.42.2.80 > 10.0.42.1.[0-9]{4,5}: Flags \[F.\]"
	tcpdump -nnr retis.pcap | grep -E "IP 10.0.42.1.[0-9]{4,5} > 10.0.42.2.80: Flags \[.\]"
	tcpdump -nnr retis.pcap | grep -E "IP 10.0.42.1.[0-9]{4,5} > 10.0.42.2.80: Flags \[F.\]"
	tcpdump -nnr retis.pcap | grep -E "IP 10.0.42.2.80 > 10.0.42.1.[0-9]{4,5}: Flags \[.\]"
}

run_tests pcap_tcp_cc
