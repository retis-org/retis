use std::fmt;

use base64::{
    display::Base64Display, engine::general_purpose::STANDARD, prelude::BASE64_STANDARD, Engine,
};
use retis_pnet::{arp::*, ethernet::*, ip::*, ipv4::*, ipv6::*, tcp::*, udp::*, vlan::*, *};

use super::*;

/// Represents a raw packet. Stored internally as a `Vec<u8>`.
/// We don't use #[event_type] as we're implementing serde::Serialize and
/// serde::Deserialize manually.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "python", derive(pyo3::IntoPyObject))]
pub struct RawPacket(pub Vec<u8>);

impl serde::Serialize for RawPacket {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&Base64Display::new(&self.0, &STANDARD))
    }
}

impl<'de> serde::Deserialize<'de> for RawPacket {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RawPacketVisitor;

        impl serde::de::Visitor<'_> for RawPacketVisitor {
            type Value = RawPacket;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("raw packet as base64 string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match BASE64_STANDARD.decode(value).map(RawPacket) {
                    Ok(v) => Ok(v),
                    Err(_) => Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(value),
                        &self,
                    )),
                }
            }
        }

        deserializer.deserialize_str(RawPacketVisitor)
    }
}

#[derive(thiserror::Error, Debug)]
enum PacketFmtError {
    #[error("Formatting error")]
    Fmt(#[from] fmt::Error),
    #[error("Payload is truncated or incomplete")]
    Truncated,
    #[error("Protocol not supported ({0})")]
    NotSupported(String),
}

type FmtResult<T> = std::result::Result<T, PacketFmtError>;

impl EventFmt for RawPacket {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result {
        // Do not propagate errors on parsing: keep things best effort (except
        // for real formatting issues).
        use PacketFmtError::*;
        match self.format_packet(f, format) {
            Err(Truncated) => write!(f, "... (truncated or incomplete packet)"),
            Err(NotSupported(p)) => write!(f, "... ({p} not supported, use 'retis pcap')"),
            Err(Fmt(e)) => Err(e),
            _ => Ok(()),
        }
    }
}

impl RawPacket {
    fn format_packet(&self, f: &mut Formatter, format: &DisplayFormat) -> FmtResult<()> {
        match EthernetPacket::new(&self.0) {
            Some(eth) => self.format_ethernet(f, format, &eth),
            None => Err(PacketFmtError::Truncated),
        }
    }

    fn format_ethernet(
        &self,
        f: &mut Formatter,
        format: &DisplayFormat,
        eth: &EthernetPacket,
    ) -> FmtResult<()> {
        let etype = match helpers::etype_str(eth.get_ethertype().0) {
            Some(etype) => etype,
            // We can report non-Ethernet packets, sanity check they look like
            // one. We could still get invalid ones, if the data at the right
            // offset looks like an Ethernet packet; but what else can we do?
            None => {
                return Err(PacketFmtError::NotSupported(format!(
                    "etype {:#06x}",
                    eth.get_ethertype().0
                )))
            }
        };

        if format.print_ll {
            write!(
                f,
                "{} > {} ethertype {etype} ({:#06x})",
                eth.get_source(),
                eth.get_destination(),
                eth.get_ethertype().0
            )?;
        }

        let (etype, payload) = self.traverse_vlan(f, format, eth.get_ethertype(), eth.payload())?;

        if format.print_ll {
            write!(f, " ")?;
        }

        match etype {
            EtherTypes::Arp => match ArpPacket::new(payload) {
                Some(arp) => self.format_arp(f, format, &arp),
                None => Err(PacketFmtError::Truncated),
            },
            EtherTypes::Ipv4 => match Ipv4Packet::new(payload) {
                Some(ip) => self.format_ipv4(f, format, &ip),
                None => Err(PacketFmtError::Truncated),
            },
            EtherTypes::Ipv6 => match Ipv6Packet::new(payload) {
                Some(ip) => self.format_ipv6(f, format, &ip),
                None => Err(PacketFmtError::Truncated),
            },
            _ => Err(PacketFmtError::NotSupported(format!(
                "etype {:#06x}",
                etype.0
            ))),
        }
    }

    fn traverse_vlan<'a>(
        &self,
        f: &mut Formatter,
        format: &DisplayFormat,
        etype: EtherType,
        payload: &'a [u8],
    ) -> FmtResult<(EtherType, &'a [u8])> {
        match etype {
            EtherTypes::Vlan | EtherTypes::PBridge | EtherTypes::QinQ => {
                match VlanPacket::new(payload) {
                    Some(vlan) => {
                        if format.print_ll {
                            self.format_vlan(f, &vlan)?;
                        }
                        self.traverse_vlan(
                            f,
                            format,
                            vlan.get_ethertype(),
                            &payload[vlan.packet_size()..],
                        )
                    }
                    None => Err(PacketFmtError::Truncated),
                }
            }
            _ => Ok((etype, payload)),
        }
    }

    fn format_vlan(&self, f: &mut Formatter, vlan: &VlanPacket) -> FmtResult<()> {
        write!(
            f,
            " vlan {} p {}{}",
            vlan.get_vlan_identifier(),
            vlan.get_priority_code_point().0,
            if vlan.get_drop_eligible_indicator() == 1 {
                " DEI"
            } else {
                ""
            },
        )?;

        let ethertype = vlan.get_ethertype();
        match helpers::etype_str(ethertype.0) {
            Some(etype) => write!(f, " ethertype {etype} ({:#06x})", ethertype.0)?,
            None => write!(f, " ethertype ({:#06x})", ethertype.0)?,
        }

        Ok(())
    }

    fn format_arp(
        &self,
        f: &mut Formatter,
        _format: &DisplayFormat,
        arp: &ArpPacket,
    ) -> FmtResult<()> {
        let sha = arp.get_sender_hw_addr();
        let tha = arp.get_target_hw_addr();
        let spa = arp.get_sender_proto_addr();
        let tpa = arp.get_target_proto_addr();

        match arp.get_operation() {
            ArpOperations::Request => {
                write!(f, "request who-has {tpa}")?;
                if !tha.is_zero() {
                    write!(f, " ({tha})")?;
                }
                write!(f, " tell {spa}")?;
            }
            ArpOperations::Reply => {
                write!(f, "reply {spa} is-at {sha}")?;
            }
            ArpOperations::ReverseRequest => write!(f, "reverse request who-is {tha} tell {sha}")?,
            ArpOperations::ReverseReply => {
                write!(f, "reverse reply {tha} at {tpa}")?;
            }
            op => {
                return Err(PacketFmtError::NotSupported(format!(
                    "ARP operation {}",
                    op.0
                )))
            }
        }

        Ok(())
    }

    fn format_ipv4(
        &self,
        f: &mut Formatter,
        format: &DisplayFormat,
        ip: &Ipv4Packet,
    ) -> FmtResult<()> {
        let ports =
            match ip.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => TcpPacket::new(ip.payload())
                    .map(|tcp| (tcp.get_source(), tcp.get_destination())),
                IpNextHeaderProtocols::Udp => UdpPacket::new(ip.payload())
                    .map(|udp| (udp.get_source(), udp.get_destination())),
                _ => None,
            };
        if let Some((sport, dport)) = ports {
            write!(
                f,
                "{}.{sport} > {}.{dport}",
                ip.get_source(),
                ip.get_destination()
            )?;
        } else {
            write!(f, "{} > {}", ip.get_source(), ip.get_destination())?;
        }

        write!(
            f,
            " tos {:#x}{} ttl {} id {} off {}",
            ip.get_dscp(),
            match ip.get_ecn() {
                1 => " ECT(1)",
                2 => " ECT(0)",
                3 => " CE",
                _ => "",
            },
            ip.get_ttl(),
            ip.get_identification(),
            ip.get_fragment_offset() * 8,
        )?;

        let mut flags = Vec::new();
        if ip.get_flags() & (1 << 2) != 0 {
            flags.push("+");
        }
        if ip.get_flags() & (1 << 1) != 0 {
            flags.push("DF");
        }
        if ip.get_flags() & 1 != 0 {
            flags.push("rsvd");
        }
        if !flags.is_empty() {
            write!(f, " [{}]", flags.join(","))?;
        }

        // In some rare cases the IP header might not be fully filled yet,
        // length might be unset.
        let len = ip.get_total_length();
        if len > 0 {
            write!(f, " len {len}")?;
        }

        let protocol = ip.get_next_level_protocol().0;
        match helpers::protocol_str(protocol) {
            Some(proto) => write!(f, " proto {proto} ({protocol})")?,
            None => write!(f, " proto ({protocol})")?,
        }

        self.format_l4(f, format, ip.get_next_level_protocol(), ip.payload())
    }

    fn format_ipv6(
        &self,
        f: &mut Formatter,
        format: &DisplayFormat,
        ip: &Ipv6Packet,
    ) -> FmtResult<()> {
        let ports =
            match ip.get_next_header() {
                IpNextHeaderProtocols::Tcp => TcpPacket::new(ip.payload())
                    .map(|tcp| (tcp.get_source(), tcp.get_destination())),
                IpNextHeaderProtocols::Udp => UdpPacket::new(ip.payload())
                    .map(|udp| (udp.get_source(), udp.get_destination())),
                _ => None,
            };
        if let Some((sport, dport)) = ports {
            write!(
                f,
                "{}.{sport} > {}.{dport}",
                ip.get_source(),
                ip.get_destination()
            )?;
        } else {
            write!(f, "{} > {}", ip.get_source(), ip.get_destination())?;
        }

        write!(
            f,
            "{} ttl {} label {:#x}",
            match ip.get_traffic_class() & 0x3 {
                1 => " ECT(1)",
                2 => " ECT(0)",
                3 => " CE",
                _ => "",
            },
            ip.get_hop_limit(),
            ip.get_flow_label(),
        )?;

        // In some rare cases the IP header might not be fully filled yet,
        // length might be unset.
        let len = ip.get_payload_length();
        if len > 0 {
            write!(f, " len {len}")?;
        }

        let protocol = ip.get_next_header().0;
        match helpers::protocol_str(protocol) {
            Some(proto) => write!(f, " proto {proto} ({protocol})")?,
            None => write!(f, " proto ({protocol})")?,
        }

        self.format_l4(f, format, ip.get_next_header(), ip.payload())
    }

    fn format_l4(
        &self,
        f: &mut Formatter,
        format: &DisplayFormat,
        protocol: IpNextHeaderProtocol,
        payload: &[u8],
    ) -> FmtResult<()> {
        match protocol {
            IpNextHeaderProtocols::Udp => match UdpPacket::new(payload) {
                Some(udp) => self.format_udp(f, format, &udp),
                None => Err(PacketFmtError::Truncated),
            },
            _ => Err(PacketFmtError::NotSupported(format!(
                "protocol {:#x}",
                protocol.0
            ))),
        }
    }

    fn format_udp(
        &self,
        f: &mut Formatter,
        _format: &DisplayFormat,
        udp: &UdpPacket,
    ) -> FmtResult<()> {
        // Substract the UDP header size when reporting the length.
        write!(f, " len {}", udp.get_length().saturating_sub(8))?;
        Ok(())
    }
}
