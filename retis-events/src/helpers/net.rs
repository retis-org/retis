//! # Networking helpers
use retis_pnet::{ethernet::*, ip::*};

/// Returns a translation of some ethertypes into a readable format.
pub fn etype_str(etype: EtherType) -> Option<&'static str> {
    Some(match etype {
        EtherTypes::Ipv4 => "IPv4",
        EtherTypes::Arp => "ARP",
        EtherTypes::Teb => "TEB",
        EtherTypes::Rarp => "Reverse ARP",
        EtherTypes::AppleTalk => "Appletalk",
        EtherTypes::Aarp => "Appletalk ARP",
        EtherTypes::Vlan => "802.1Q",
        EtherTypes::Ipv6 => "IPv6",
        EtherTypes::Ppp => "PPP",
        EtherTypes::Mpls => "MPLS unicast",
        EtherTypes::MplsMcast => "MPLS multicast",
        EtherTypes::PppoeDiscovery => "PPPoE D",
        EtherTypes::PppoeSession => "PPPoE S",
        EtherTypes::Eapol => "EAPOL",
        EtherTypes::PBridge => "802.1Q-QinQ",
        EtherTypes::Macsec => "802.1AE MACsec",
        EtherTypes::Ptp => "PTP",
        EtherTypes::QinQ => "802.1Q-9100",
        _ => return None,
    })
}

/// Returns a translation of some protocols into a readable format.
pub(crate) fn protocol_str(protocol: IpNextHeaderProtocol) -> Option<&'static str> {
    Some(match protocol {
        IpNextHeaderProtocols::Icmp => "ICMP",
        IpNextHeaderProtocols::Igmp => "IGMP",
        IpNextHeaderProtocols::Ipv4 => "IPIP",
        IpNextHeaderProtocols::Tcp => "TCP",
        IpNextHeaderProtocols::Udp => "UDP",
        IpNextHeaderProtocols::Rdp => "RDP",
        IpNextHeaderProtocols::Dccp => "DCCP",
        IpNextHeaderProtocols::Ipv6 => "IPv6",
        IpNextHeaderProtocols::Gre => "GRE",
        IpNextHeaderProtocols::Esp => "ESP",
        IpNextHeaderProtocols::Ah => "AH",
        IpNextHeaderProtocols::Icmpv6 => "ICMPv6",
        IpNextHeaderProtocols::OspfigP => "OSPF",
        IpNextHeaderProtocols::Vrrp => "VRRP",
        IpNextHeaderProtocols::L2tp => "L2TP",
        IpNextHeaderProtocols::Sctp => "SCTP",
        IpNextHeaderProtocols::Ethernet => "Ethernet",
        _ => return None,
    })
}
