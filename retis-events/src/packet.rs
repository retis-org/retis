use std::{fmt, str};

use base64::{
    display::Base64Display, engine::general_purpose::STANDARD, prelude::BASE64_STANDARD, Engine,
};
use retis_pnet::{
    arp::*, ethernet::*, geneve::*, icmp::*, icmpv6::*, ip::*, ipv4::*, ipv6::*, tcp::*, udp::*,
    vlan::*, vxlan::*, *,
};

#[cfg(feature = "python")]
use {
    pyo3::{exceptions::*, prelude::*, types::*},
    std::ffi::CString,
};

use super::*;

/// Raw packet and related metadata.
#[event_section(SectionId::Packet)]
pub struct PacketEvent {
    /// Length of the packet.
    pub len: u32,
    /// Lenght of the capture. <= len.
    pub capture_len: u32,
    /// Raw packet data.
    pub data: RawPacket,
}

#[allow(dead_code)]
#[cfg(feature = "python")]
#[cfg_attr(feature = "python", pymethods)]
impl PacketEvent {
    /// Forward the `to_scapy` method down to the RawPacket.
    fn to_scapy(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.data.to_scapy(py)
    }
}

impl EventFmt for PacketEvent {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result {
        self.data.event_fmt(f, format)
    }
}

/// Represents a raw packet. Stored internally as a `Vec<u8>`.
/// We don't use #[event_type] as we're implementing serde::Serialize and
/// serde::Deserialize manually.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "python", pyclass)]
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

#[allow(dead_code)]
#[cfg(feature = "python")]
#[cfg_attr(feature = "python", pymethods)]
impl RawPacket {
    fn __repr__(&self, py: Python<'_>) -> String {
        self.__bytes__(py).to_string()
    }

    fn __bytes__(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.0).into()
    }

    pub(crate) fn to_scapy(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match py.import("scapy.all") {
            Ok(scapy) => {
                let locals = [("scapy", scapy)].into_py_dict(py)?;
                let packet = PyBytes::new(py, &self.0);
                let ins = CString::new(format!("scapy.Ether({packet})"))?;
                Ok(py.eval(ins.as_c_str(), None, Some(&locals))?.into())
            }
            Err(_) => Err(PyImportError::new_err("Could not import scapy.all")),
        }
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
        let etype = match helpers::etype_str(eth.get_ethertype()) {
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
        match helpers::etype_str(ethertype) {
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

        // Handle IPv4 options.
        let mut opts = Vec::new();
        for opt in ip.get_options_iter() {
            match opt.get_number() {
                // EOL and padding are more or less the same thing. Only show
                // the EOL option if it is a genuine one.
                Ipv4OptionNumbers::EOL => {
                    if !opts.is_empty() {
                        opts.push(format!("{:?}", opt.get_number()))
                    }
                    break;
                }
                _ => opts.push(format!("{:?}", opt.get_number())),
            }
        }
        if !opts.is_empty() {
            write!(f, " opts [{}]", opts.join(","))?;
        }

        let protocol = ip.get_next_level_protocol();
        match helpers::protocol_str(protocol) {
            Some(proto) => write!(f, " proto {proto} ({})", protocol.0)?,
            None => write!(f, " proto ({})", protocol.0)?,
        }

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
        let mut prev_protocol = protocol;
        let mut len = ip.get_payload_length() as u32;
        let mut payload = ip.payload();
        let mut exts = Vec::new();

        // Skip IPv6 extensions.
        let extensions = ExtensionIterable::from(ip);
        extensions.for_each(|ext| {
            exts.push(format!("{protocol}"));
            prev_protocol = protocol;
            protocol = ext.get_next_header();
            // Using `packet_size` works because the payload isn't part of the
            // extension "packets".
            len = len.saturating_sub(ext.packet_size() as u32);
            payload = &payload[ext.packet_size()..];
        });

        if !exts.is_empty() {
            write!(f, " exts [{}]", exts.join(","),)?;
        }

        // Payload, if any, is garbage.
        if prev_protocol == IpNextHeaderProtocols::Ipv6NoNxt {
            return Ok(());
        }

        match helpers::protocol_str(protocol) {
            Some(proto) => write!(f, " proto {proto} ({})", protocol.0)?,
            None => write!(f, " proto ({})", protocol.0)?,
        }

        // ESP is valid but the payload might be unparsable, provide the len and
        // skip for now.
        if prev_protocol == IpNextHeaderProtocols::Esp {
            write!(f, " len {len}")?;
            return Err(PacketFmtError::NotSupported("ESP packet".to_string()));
        }

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
            4789 | 8472 => match VxlanPacket::new(udp.payload()) {
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
            off if off > 0 => write!(f, " seq {seq}:{}", seq + off)?,
            _ => write!(f, " seq {seq}")?,
        }

        if tcp_flags & TcpFlags::ACK != 0 {
            write!(f, " ack {}", tcp.get_acknowledgement())?;
        }

        write!(f, " win {}", tcp.get_window())?;

        if (tcp.get_data_offset() * 4).saturating_sub(20) > 0 {
            write!(f, " [")?;
            let mut sep = DelimWriter::new(',');

            for opt in tcp.get_options_iter() {
                let optnum = opt.get_number();
                let datalen = match opt.get_length_raw().first() {
                    Some(len) if *len >= 2 => *len as usize - 2,
                    _ => 0,
                };

                sep.write(f)?;
                write!(
                    f,
                    "{}",
                    match optnum {
                        TcpOptionNumbers::EOL => "eol",
                        TcpOptionNumbers::NOP => "nop",
                        TcpOptionNumbers::MSS => "mss",
                        TcpOptionNumbers::WSCALE => "wscale",
                        TcpOptionNumbers::SACK_PERMITTED => "sackOK",
                        TcpOptionNumbers::SACK => "sack",
                        TcpOptionNumbers::ECHO => "echo",
                        TcpOptionNumbers::ECHO_REPLY => "echoreply",
                        TcpOptionNumbers::TIMESTAMPS => "TS",
                        TcpOptionNumbers::CC => "cc",
                        TcpOptionNumbers::CC_NEW => "ccnew",
                        TcpOptionNumbers::CC_ECHO => "ccecho",
                        TcpOptionNumbers::MD5 => "md5",
                        TcpOptionNumbers::SCPS => "scps",
                        TcpOptionNumbers::UTO => "uto",
                        TcpOptionNumbers::TCP_AO => "tcp-ao",
                        TcpOptionNumbers::MPTCP => "mptcp",
                        TcpOptionNumbers::TFO => "tfo",
                        TcpOptionNumbers::EXP_2 => "exp",
                        _ => "?",
                    }
                )?;

                match optnum {
                    TcpOptionNumbers::MSS => {
                        if let Some(mss) = opt.payload().get(..2) {
                            write!(f, " {}", u16::from_be_bytes(mss.try_into().unwrap()))?;
                        }
                    }
                    TcpOptionNumbers::WSCALE => {
                        if let Some(len) = opt.payload().first() {
                            write!(f, " {len}")?;
                        }
                    }
                    TcpOptionNumbers::SACK => {
                        if datalen % 8 != 0 {
                            write!(f, " invalid")?;
                        } else {
                            write!(f, " {} ", datalen / 8)?;

                            for i in (0..datalen).step_by(8) {
                                if let Some(sack) = opt.payload().get(i..(i + 8)) {
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
                    TcpOptionNumbers::ECHO
                    | TcpOptionNumbers::ECHO_REPLY
                    | TcpOptionNumbers::CC
                    | TcpOptionNumbers::CC_NEW
                    | TcpOptionNumbers::CC_ECHO => {
                        if let Some(val) = opt.payload().get(..4) {
                            write!(f, " {}", u32::from_be_bytes(val.try_into().unwrap()))?;
                        }
                    }
                    TcpOptionNumbers::TIMESTAMPS => {
                        if let Some(ts) = opt.payload().get(..8) {
                            write!(
                                f,
                                " val {} ecr {}",
                                u32::from_be_bytes(ts[0..4].try_into().unwrap()),
                                u32::from_be_bytes(ts[4..8].try_into().unwrap()),
                            )?;
                        }
                    }
                    TcpOptionNumbers::MPTCP => {
                        // FIXME
                    }
                    TcpOptionNumbers::TFO => {
                        if datalen == 0 {
                            write!(f, " cookiereq")?;
                        } else {
                            write!(f, " cookie ")?;
                            for i in 0..datalen {
                                if let Some(c) = opt.payload().get(i) {
                                    write!(f, "{c:#02x}")?;
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

        write!(
            f,
            " geneve [{}] vni {:#x}",
            flags.into_iter().collect::<String>(),
            geneve.get_vni(),
        )?;

        let protocol = geneve.get_protocol();
        if format.print_ll {
            match helpers::etype_str(protocol) {
                Some(etype) => write!(f, " proto {etype} ({:#06x})", protocol.0)?,
                None => write!(f, " proto ({:#06x})", protocol.0)?,
            }
        }

        if geneve.get_options_len() > 0 {
            write!(f, " opts_len {}", geneve.get_options_len() * 4)?;
        }

        write!(f, " ")?;
        match protocol {
            EtherTypes::Teb => match EthernetPacket::new(geneve.payload()) {
                Some(eth) => self.format_ethernet(f, format, &eth),
                None => Err(PacketFmtError::Truncated),
            },
            _ => self.format_l3(f, format, protocol, geneve.payload()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DisplayFormat, FormatterConf};

    #[test]
    fn print_icmp_in_geneve() {
        let mut buf = Vec::new();
        BASE64_STANDARD.decode_vec(
            "ukoiHKOOzikYufsvCABFAACGORIAAEAR2VIKACoBCgAqAkL5F8EAcmiGAABlWAAAAQAO2mLRzBfW99tozRgIAEUAAFRH90AAQAGIrwoAKwEKACsCCAA5rgUFAAE5cv5nAAAAAL+eAwAAAAAAEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nw==",
            &mut buf,
        ).unwrap();
        let raw = RawPacket(buf);

        assert_eq!(
            &format!("{}", raw.display(&DisplayFormat::new(), &FormatterConf::new())),
            "10.0.42.1.17145 > 10.0.42.2.6081 tos 0x0 ttl 64 id 14610 off 0 len 134 proto UDP (17) len 106 geneve [] vni 0x1 10.0.43.1 > 10.0.43.2 tos 0x0 ttl 64 id 18423 off 0 [DF] len 84 proto ICMP (1) type 8 code 0",
        );
    }

    #[test]
    fn print_tcp6_in_vlan() {
        let mut buf = Vec::new();
        BASE64_STANDARD.decode_vec(
            "rrBKar+vnh09MZ47ht1gBvSKACgGQBERAAAAAAAAAAAAAAAAAAEREQAAAAAAAAAAAAAAAAAC22QAULIRwcAAAAAAoAL9ICJTAAACBAWgBAIIClP9HoIAAAAAAQMDBw==",
            &mut buf,
        ).unwrap();
        let raw = RawPacket(buf);

        assert_eq!(
            &format!("{}", raw.display(&DisplayFormat::new().print_ll(true), &FormatterConf::new())),
            "9e:1d:3d:31:9e:3b > ae:b0:4a:6a:bf:af ethertype IPv6 (0x86dd) 1111::1.56164 > 1111::2.80 ttl 64 label 0x6f48a len 40 proto TCP (6) flags [S] seq 2987508160 win 64800 [mss 1440,sackOK,TS val 1409097346 ecr 0,nop,wscale 7]"
        );
    }
}
