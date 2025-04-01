/// Networking utilities
use std::fmt;

use base64::{
    display::Base64Display, engine::general_purpose::STANDARD, prelude::BASE64_STANDARD, Engine,
};
use retis_pnet::{
    arp::*, ethernet::*, geneve::*, icmp::*, icmpv6::*, ip::*, ipv4::*, ipv6::*, tcp::*, udp::*,
    vlan::*, vxlan::*, *,
};

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
    #[error("Parsing error ({0})")]
    Parsing(String),
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
            Err(Parsing(e)) => write!(f, "... (parsing error: {e})"),
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
                    "ethertype {:#06x}",
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

        self.format_l3(f, format, etype, payload)
    }

    fn format_l3(
        &self,
        f: &mut Formatter,
        format: &DisplayFormat,
        etype: EtherType,
        payload: &[u8],
    ) -> FmtResult<()> {
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
                "ethertype {:#06x}",
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
            EtherTypes::Vlan | EtherTypes::PBridge => match VlanPacket::new(payload) {
                Some(vlan) => {
                    if format.print_ll {
                        self.format_vlan(f, &vlan)?;
                    }
                    self.traverse_vlan(f, format, vlan.get_ethertype(), &payload[4..])
                }
                None => Err(PacketFmtError::Truncated),
            },
            _ => Ok((etype, payload)),
        }
    }

    fn format_vlan(&self, f: &mut Formatter, vlan: &VlanPacket) -> FmtResult<()> {
        write!(
            f,
            " vlan {} p {}{} ethertype {} ({:#06x})",
            vlan.get_vlan_identifier(),
            vlan.get_priority_code_point().0,
            if vlan.get_drop_eligible_indicator() == 1 {
                " DEI"
            } else {
                ""
            },
            match helpers::etype_str(vlan.get_ethertype().0) {
                Some(etype) => etype,
                None =>
                    return Err(PacketFmtError::NotSupported(format!(
                        "ethertype {:#06x}",
                        vlan.get_ethertype().0
                    ))),
            },
            vlan.get_ethertype().0,
        )?;
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

        match arp.get_operation().0 {
            // Request
            1 => {
                write!(f, "request who-has ")?;
                format_ipv4_addr(f, u32::from(tpa))?;
                if !tha.is_zero() {
                    write!(f, " ({tha})")?;
                }
                write!(f, " tell ")?;
                format_ipv4_addr(f, u32::from(spa))?;
            }
            // Reply
            2 => {
                write!(f, "reply ")?;
                format_ipv4_addr(f, u32::from(spa))?;
                write!(f, " is-at {sha}")?;
            }
            // Reverse request
            3 => write!(f, "reverse request who-is {tha} tell {sha}")?,
            // Reverse reply
            4 => {
                write!(f, "reverse reply {tha} at ")?;
                format_ipv4_addr(f, u32::from(tpa))?;
            }
            op => return Err(PacketFmtError::NotSupported(format!("ARP operation {op}"))),
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
            format_ipv4_addr(f, u32::from(ip.get_source()))?;
            write!(f, ".{sport} > ")?;
            format_ipv4_addr(f, u32::from(ip.get_destination()))?;
            write!(f, ".{dport}")?;
        } else {
            format_ipv4_addr(f, u32::from(ip.get_source()))?;
            write!(f, " > ")?;
            format_ipv4_addr(f, u32::from(ip.get_destination()))?;
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

        let opts = ip
            .get_options_iter()
            .map(|o| format!("{:?}", o.get_number()))
            .collect::<Vec<_>>();
        if !opts.is_empty() {
            write!(f, " opts [{}]", opts.join(","))?;
        }

        let protocol = ip.get_next_level_protocol().0;
        if let Some(proto) = helpers::protocol_str(protocol) {
            write!(f, " proto {proto}")?;
        }
        write!(f, " ({protocol})")?;

        self.format_l4(
            f,
            format,
            ip.get_next_level_protocol(),
            ip.payload(),
            (ip.get_total_length() as u32).saturating_sub(ip.get_header_length() as u32 * 4),
        )
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

        let mut protocol = ip.get_next_header();
        let mut len = ip.get_payload_length() as u32;
        let mut payload = ip.payload();

        // Check if the next header is an IPv6 extension.
        use IpNextHeaderProtocols::*;
        let is_extension = |protocol| match protocol {
            #[allow(non_upper_case_globals)]
            Hopopt | Ipv6Route | Ipv6Frag | Ah | Ipv6NoNxt | Ipv6Opts | MobilityHeader | Hip
            | Shim6 | Test1 | Test2 => true,
            _ => false,
        };

        // Skip IPv6 extensions.
        while is_extension(protocol) {
            let mut exts = vec![format!("{protocol}")];
            match ExtensionPacket::new(payload) {
                Some(ext) => {
                    protocol = ext.get_next_header();
                    len = ext.get_hdr_ext_len() as u32 * 8 + 8 - 2;
                    payload = &payload[(len as usize + 2)..];

                    exts.push(format!("{protocol}"));
                }
                None => return Err(PacketFmtError::Truncated),
            }
            write!(f, " exts [{}]", exts.join(","),)?;
        }

        if let Some(proto) = helpers::protocol_str(protocol.0) {
            write!(f, " proto {proto}")?;
        }
        write!(f, " ({})", protocol.0)?;

        self.format_l4(f, format, protocol, payload, len)
    }

    fn format_l4(
        &self,
        f: &mut Formatter,
        format: &DisplayFormat,
        protocol: IpNextHeaderProtocol,
        payload: &[u8],
        payload_len: u32,
    ) -> FmtResult<()> {
        match protocol {
            IpNextHeaderProtocols::Udp => match UdpPacket::new(payload) {
                Some(udp) => self.format_udp(f, format, &udp),
                None => Err(PacketFmtError::Truncated),
            },
            IpNextHeaderProtocols::Tcp => match TcpPacket::new(payload) {
                Some(tcp) => self.format_tcp(f, format, &tcp, payload_len),
                None => Err(PacketFmtError::Truncated),
            },
            IpNextHeaderProtocols::Icmp => match IcmpPacket::new(payload) {
                Some(icmp) => self.format_icmp(f, format, &icmp),
                None => Err(PacketFmtError::Truncated),
            },
            IpNextHeaderProtocols::Icmpv6 => match Icmpv6Packet::new(payload) {
                Some(icmp) => self.format_icmpv6(f, format, &icmp),
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
        format: &DisplayFormat,
        udp: &UdpPacket,
    ) -> FmtResult<()> {
        // Substract the UDP header size when reporting the length.
        write!(f, " len {}", udp.get_length().saturating_sub(8))?;

        match udp.get_destination() {
            4789 => match VxlanPacket::new(udp.payload()) {
                Some(vxlan) => self.format_vxlan(f, format, &vxlan),
                None => Err(PacketFmtError::Truncated),
            },
            6081 => match GenevePacket::new(udp.payload()) {
                Some(geneve) => self.format_geneve(f, format, &geneve),
                None => Err(PacketFmtError::Truncated),
            },
            _ => Ok(()),
        }
    }

    fn format_tcp(
        &self,
        f: &mut Formatter,
        _format: &DisplayFormat,
        tcp: &TcpPacket,
        payload_len: u32,
    ) -> FmtResult<()> {
        let tcp_flags = tcp.get_flags();

        let mut flags = Vec::new();
        if tcp_flags & TcpFlags::FIN != 0 {
            flags.push('F');
        }
        if tcp_flags & TcpFlags::SYN != 0 {
            flags.push('S');
        }
        if tcp_flags & TcpFlags::RST != 0 {
            flags.push('R');
        }
        if tcp_flags & TcpFlags::PSH != 0 {
            flags.push('P');
        }
        if tcp_flags & TcpFlags::ACK != 0 {
            flags.push('.');
        }
        if tcp_flags & TcpFlags::URG != 0 {
            flags.push('U');
        }
        if tcp_flags & TcpFlags::ECE != 0 {
            flags.push('E');
        }
        if tcp_flags & TcpFlags::CWR != 0 {
            flags.push('W');
        }
        if tcp.get_reserved() & 1 != 0 {
            /* RFC7560 */
            flags.push('e');
        }
        write!(f, " flags [{}]", flags.into_iter().collect::<String>())?;

        let seq = tcp.get_sequence();
        match payload_len.saturating_sub(tcp.get_data_offset() as u32 * 4) {
            off if off > 0 => write!(f, " seq {seq}:{}", tcp.get_sequence() + off)?,
            _ => write!(f, " seq {seq}")?,
        }

        if tcp_flags & (1 << 4) != 0 {
            write!(f, " ack {}", tcp.get_acknowledgement())?;
        }

        write!(f, " win {}", tcp.get_window())?;

        if (tcp.get_data_offset() * 4).saturating_sub(20) > 0 {
            write!(f, " [")?;
            let mut sep = DelimWriter::new(',');

            for opt in tcp.get_options_iter() {
                let optnum = opt.get_number().0;
                let datalen = match opt.get_length_raw().first() {
                    Some(len) if *len >= 2 => *len as usize - 2,
                    _ => 0,
                };

                sep.write(f)?;
                write!(
                    f,
                    "{}",
                    match optnum {
                        0 => "eol",
                        1 => "nop",
                        2 => "mss",
                        3 => "wscale",
                        4 => "sackOK",
                        5 => "sack",
                        6 => "echo",
                        7 => "echoreply",
                        8 => "TS",
                        11 => "cc",
                        12 => "ccnew",
                        13 => "ccecho",
                        19 => "md5",
                        20 => "scps",
                        28 => "uto",
                        29 => "tcp-ao",
                        30 => "mptcp",
                        34 => "tfo",
                        254 => "exp",
                        _ => "?",
                    }
                )?;

                match optnum {
                    2 /* MSS */ => {
                        if let Some(mss) = opt.payload().get(..2) {
                            write!(f, " {}", u16::from_be_bytes(mss.try_into().unwrap()))?;
                        }
                    }
                    3 /* WSCALE */ => {
                        if let Some(len) = opt.payload().first() {
                            write!(f, " {len}")?;
                        }
                    }
                    5 /* SACK */ => {
                        if datalen % 8 != 0 {
                            write!(f, " invalid")?;
                        } else {
                            write!(f, " {} ", datalen / 8)?;

                            for i in (0..datalen).step_by(8) {
                                if let Some(sack) = opt.payload().get(i..(i+8)) {
                                    write!(
                                        f,
                                        "{{{}:{}}}",
                                        u32::from_be_bytes(sack[0..4].try_into().unwrap()),
                                        u32::from_be_bytes(sack[4..8].try_into().unwrap()),
                                    )?;
                                }
                            }
                        }
                    }
                    6 /* echo */ |
                    7 /* echoreply */ |
                    11 /* cc */ |
                    12 /* ccnew */ |
                    13 /* ccecho */ => {
                        if let Some(val) = opt.payload().get(..4) {
                            write!(f, " {}", u32::from_be_bytes(val.try_into().unwrap()))?;
                        }
                    }
                    8 /* TS */ => if let Some(ts) = opt.payload().get(..8) {
                        write!(
                            f,
                            " val {} ecr {}",
                            u32::from_be_bytes(ts[0..4].try_into().unwrap()),
                            u32::from_be_bytes(ts[4..8].try_into().unwrap()),
                        )?;
                    }
                    30 /* MPTCP */ => {
                        // FIXME
                    }
                    34 /* TFO */ => {
                        if datalen == 0 {
                            write!(f, " cookiereq")?;
                        } else {
                            write!(f, " cookie ")?;
                            for i in 0..datalen {
                                if let Some(c) = opt.payload().get(i) {
                                    write!(f, "{:#02x}", c)?;
                                } else {
                                    write!(f, "??")?;
                                }
                            }
                        }
                    }
                    _ => continue,
                }
            }

            write!(f, "]")?;
        }

        Ok(())
    }

    fn format_icmp(
        &self,
        f: &mut Formatter,
        _format: &DisplayFormat,
        icmp: &IcmpPacket,
    ) -> FmtResult<()> {
        write!(
            f,
            " type {} code {}",
            icmp.get_icmp_type().0,
            icmp.get_icmp_code().0
        )?;
        Ok(())
    }

    fn format_icmpv6(
        &self,
        f: &mut Formatter,
        _format: &DisplayFormat,
        icmp: &Icmpv6Packet,
    ) -> FmtResult<()> {
        write!(
            f,
            " type {} code {}",
            icmp.get_icmpv6_type().0,
            icmp.get_icmpv6_code().0
        )?;
        Ok(())
    }

    fn format_vxlan(
        &self,
        f: &mut Formatter,
        format: &DisplayFormat,
        vxlan: &VxlanPacket,
    ) -> FmtResult<()> {
        write!(
            f,
            " vxlan [{}] vni {:#x}",
            if vxlan.get_flags() & (1 << 3) != 0 {
                "I"
            } else {
                ""
            },
            vxlan.get_vni(),
        )?;

        write!(f, " ")?;
        match EthernetPacket::new(vxlan.payload()) {
            Some(eth) => self.format_ethernet(f, format, &eth),
            None => Err(PacketFmtError::Truncated),
        }
    }

    fn format_geneve(
        &self,
        f: &mut Formatter,
        format: &DisplayFormat,
        geneve: &GenevePacket,
    ) -> FmtResult<()> {
        let mut flags = Vec::new();
        if geneve.get_control() == 1 {
            flags.push("O");
        }
        if geneve.get_critical() == 1 {
            flags.push("C");
        }

        let rsvd = geneve.get_reserved0();
        if rsvd & (1 << 5) != 0 {
            flags.push("R1");
        }
        if rsvd & (1 << 4) != 0 {
            flags.push("R2");
        }
        if rsvd & (1 << 3) != 0 {
            flags.push("R3");
        }
        if rsvd & (1 << 2) != 0 {
            flags.push("R4");
        }
        if rsvd & (1 << 1) != 0 {
            flags.push("R5");
        }
        if rsvd & 1 != 0 {
            flags.push("R6");
        }

        write!(
            f,
            " geneve [{}] vni {:#x}",
            flags.into_iter().collect::<String>(),
            geneve.get_vni(),
        )?;

        if geneve.get_reserved1() != 0 {
            write!(f, "rsvd {:#x}", geneve.get_reserved1())?;
        }

        let protocol = geneve.get_protocol();
        if format.print_ll {
            match helpers::etype_str(protocol.0) {
                Some(etype) => write!(f, " proto {etype} ({:#06x})", protocol.0)?,
                None => write!(f, " proto ({:#06x})", protocol.0)?,
            }
        }

        if geneve.get_options_len() > 0 {
            write!(f, " opts_len {}", geneve.get_options_len())?;
        }

        match protocol.0 {
            // TEB.
            0x6558 => {
                write!(f, " ")?;
                match EthernetPacket::new(geneve.payload()) {
                    Some(eth) => self.format_ethernet(f, format, &eth),
                    None => Err(PacketFmtError::Truncated),
                }
            }
            _ => self.format_l3(f, format, protocol, geneve.payload()),
        }
    }
}

/// Formats an IPv4 address.
fn format_ipv4_addr(f: &mut Formatter, raw: u32) -> FmtResult<()> {
    let u8_to_utf8 = |f: &mut Formatter, mut input: u32| -> FmtResult<()> {
        let mut push = false;

        for ord in [100, 10, 1] {
            let current = input / ord;
            input %= ord;

            // Do not push leading 0s but always push the last number in case
            // all we got was 0s.
            if push || current != 0 || ord == 1 {
                push = true;
                match char::from_digit(current, 10) {
                    Some(digit) => write!(f, "{digit}")?,
                    None => return Err(PacketFmtError::Parsing("IPv4 address".to_string())),
                }
            }
        }

        Ok(())
    };

    u8_to_utf8(f, raw >> 24)?;
    write!(f, ".")?;
    u8_to_utf8(f, (raw >> 16) & 0xff)?;
    write!(f, ".")?;
    u8_to_utf8(f, (raw >> 8) & 0xff)?;
    write!(f, ".")?;
    u8_to_utf8(f, raw & 0xff)
}
