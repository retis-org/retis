/// Returns a translation of some ethertypes into a readable format.
pub(super) fn etype_str(etype: u16) -> Option<&'static str> {
    Some(match etype {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x8035 => "Reverse ARP",
        0x809b => "Appletalk",
        0x80f3 => "Appletalk ARP",
        0x8100 => "802.1Q",
        0x86dd => "IPv6",
        0x880b => "PPP",
        0x8847 => "MPLS unicast",
        0x8848 => "MPLS multicast",
        0x8863 => "PPPoE D",
        0x8864 => "PPPoE S",
        0x888e => "EAPOL",
        0x88a8 => "802.1Q QinQ",
        0x88e5 => "802.1AE MACsec",
        0x88f7 => "PTP",
        _ => return None,
    })
}

/// Returns a translation of some protocols into a readable format.
pub(super) fn protocol_str(protocol: u8) -> Option<&'static str> {
    Some(match protocol {
        1 => "ICMP",
        2 => "IGMP",
        4 => "IPIP",
        6 => "TCP",
        17 => "UDP",
        27 => "RDP",
        33 => "DCCP",
        41 => "IPv6",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        112 => "VRRP",
        115 => "L2TP",
        132 => "SCTP",
        143 => "Ethernet",
        _ => return None,
    })
}

/// Parses an Ethernet address into a String.
pub(super) fn parse_eth_addr(raw: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5],
    )
}
