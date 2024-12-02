//! Rust<>BPF types definitions for the skb module. Fields are not translated in
//! the BPF part and can be represented in various orders, depending from where
//! they come from. Some handling might be needed in the unmarshalers.
//!
//! Please keep this file in sync with its BPF counterpart in bpf/skb_hook.bpf.c

use anyhow::bail;
use std::str;

use anyhow::{anyhow, Result};
use pnet_packet::{
    arp::ArpPacket, ethernet::*, icmp::IcmpPacket, icmpv6::Icmpv6Packet, ip::*, ipv4::*, ipv6::*,
    tcp::TcpPacket, udp::UdpPacket, Packet,
};

use crate::{
    bindings::skb_hook_uapi::*,
    core::events::{
        parse_raw_section, BpfRawSection, EventSectionFactory, FactoryId, RawEventSectionFactory,
    },
    event_section_factory,
    events::{
        helpers::{etype_str, RawPacket},
        *,
    },
    helpers,
};

pub(super) fn unmarshal_eth(eth: &EthernetPacket) -> Result<SkbEthEvent> {
    Ok(SkbEthEvent {
        etype: eth.get_ethertype().0,
        src: helpers::net::parse_eth_addr(&eth.get_source().octets())?,
        dst: helpers::net::parse_eth_addr(&eth.get_destination().octets())?,
    })
}

pub(super) fn unmarshal_arp(arp: &ArpPacket) -> Result<Option<SkbArpEvent>> {
    let operation = match arp.get_operation().0 {
        1 => ArpOperation::Request,
        2 => ArpOperation::Reply,
        // We only support ARP for IPv4 over Ethernet; request & reply */
        _ => return Ok(None),
    };

    Ok(Some(SkbArpEvent {
        operation,
        sha: helpers::net::parse_eth_addr(&arp.get_sender_hw_addr().octets())?,
        spa: helpers::net::parse_ipv4_addr(u32::from(arp.get_sender_proto_addr()))?,
        tha: helpers::net::parse_eth_addr(&arp.get_target_hw_addr().octets())?,
        tpa: helpers::net::parse_ipv4_addr(u32::from(arp.get_target_proto_addr()))?,
    }))
}

pub(super) fn unmarshal_ipv4(ip: &Ipv4Packet) -> Result<SkbIpEvent> {
    Ok(SkbIpEvent {
        saddr: helpers::net::parse_ipv4_addr(u32::from(ip.get_source()))?,
        daddr: helpers::net::parse_ipv4_addr(u32::from(ip.get_destination()))?,
        version: SkbIpVersion::V4 {
            v4: SkbIpv4Event {
                tos: ip.get_dscp(),
                flags: ip.get_flags(),
                id: ip.get_identification(),
                offset: ip.get_fragment_offset(),
            },
        },
        protocol: ip.get_next_level_protocol().0,
        len: ip.get_total_length(),
        ttl: ip.get_ttl(),
        ecn: ip.get_ecn(),
    })
}

pub(super) fn unmarshal_ipv6(ip: &Ipv6Packet) -> Result<SkbIpEvent> {
    Ok(SkbIpEvent {
        saddr: ip.get_source().to_string(),
        daddr: ip.get_destination().to_string(),
        version: SkbIpVersion::V6 {
            v6: SkbIpv6Event {
                flow_label: ip.get_flow_label(),
            },
        },
        protocol: ip.get_next_header().0,
        len: ip.get_payload_length(),
        ttl: ip.get_hop_limit(),
        ecn: ip.get_traffic_class() & 0x3,
    })
}

pub(super) fn unmarshal_tcp(tcp: &TcpPacket) -> Result<SkbTcpEvent> {
    Ok(SkbTcpEvent {
        sport: tcp.get_source(),
        dport: tcp.get_destination(),
        seq: tcp.get_sequence(),
        ack_seq: tcp.get_acknowledgement(),
        window: tcp.get_window(),
        doff: tcp.get_data_offset(),
        flags: tcp.get_flags(),
    })
}

pub(super) fn unmarshal_udp(udp: &UdpPacket) -> Result<SkbUdpEvent> {
    Ok(SkbUdpEvent {
        sport: udp.get_source(),
        dport: udp.get_destination(),
        len: udp.get_length(),
    })
}

pub(super) fn unmarshal_icmp(icmp: &IcmpPacket) -> Result<SkbIcmpEvent> {
    Ok(SkbIcmpEvent {
        r#type: icmp.get_icmp_type().0,
        code: icmp.get_icmp_code().0,
    })
}

pub(super) fn unmarshal_icmpv6(icmp: &Icmpv6Packet) -> Result<SkbIcmpV6Event> {
    Ok(SkbIcmpV6Event {
        r#type: icmp.get_icmpv6_type().0,
        code: icmp.get_icmpv6_code().0,
    })
}

/// Unmarshal net device info. Can return Ok(None) in case the info does not
/// look like it's genuine (see below).
pub(super) fn unmarshal_dev(raw_section: &BpfRawSection) -> Result<Option<SkbDevEvent>> {
    let raw = parse_raw_section::<skb_netdev_event>(raw_section)?;

    // Retrieving information from `skb->dev` is tricky as this is inside an
    // union and there is no way we can know of the data is valid. Try our best
    // below to report an empty section if the data does not look like what it
    // should.
    let dev_name = match str::from_utf8(&raw.dev_name) {
        Ok(s) => s.trim_end_matches(char::from(0)),
        Err(_) => return Ok(None),
    };

    // Not much more we can do, construct the event section.
    let mut event = SkbDevEvent {
        name: dev_name.to_string(),
        ifindex: raw.ifindex,
        ..Default::default()
    };
    if raw.iif > 0 {
        event.rx_ifindex = Some(raw.iif);
    }

    Ok(Some(event))
}

pub(super) fn unmarshal_ns(raw_section: &BpfRawSection) -> Result<SkbNsEvent> {
    let raw = parse_raw_section::<skb_netns_event>(raw_section)?;

    Ok(SkbNsEvent { netns: raw.netns })
}

pub(super) fn unmarshal_meta(raw_section: &BpfRawSection) -> Result<SkbMetaEvent> {
    let raw = parse_raw_section::<skb_meta_event>(raw_section)?;

    Ok(SkbMetaEvent {
        len: raw.len,
        data_len: raw.data_len,
        hash: raw.hash,
        ip_summed: raw.ip_summed,
        csum: raw.csum,
        csum_level: raw.csum_level,
        priority: raw.priority,
    })
}

pub(super) fn unmarshal_data_ref(raw_section: &BpfRawSection) -> Result<SkbDataRefEvent> {
    let raw = parse_raw_section::<skb_data_ref_event>(raw_section)?;

    Ok(SkbDataRefEvent {
        nohdr: raw.nohdr == 1,
        cloned: raw.cloned == 1,
        fclone: raw.fclone,
        users: raw.users,
        dataref: raw.dataref,
    })
}

pub(super) fn unmarshal_gso(raw_section: &BpfRawSection) -> Result<SkbGsoEvent> {
    let raw = parse_raw_section::<skb_gso_event>(raw_section)?;

    Ok(SkbGsoEvent {
        flags: raw.flags,
        frags: raw.nr_frags,
        size: raw.gso_size,
        segs: raw.gso_segs,
        r#type: raw.gso_type,
    })
}

pub(super) fn unmarshal_packet(
    event: &mut SkbEvent,
    raw_section: &BpfRawSection,
    report_eth: bool,
) -> Result<()> {
    let raw = parse_raw_section::<skb_packet_event>(raw_section)?;

    // First add the raw packet part in the event.
    event.packet = Some(SkbPacketEvent {
        len: raw.len,
        capture_len: raw.capture_len,
        packet: RawPacket(raw.packet[..(raw.capture_len as usize)].to_vec()),
    });

    // Then start parsing the raw packet to generate other sections.
    let eth = EthernetPacket::new(&raw.packet[..(raw.capture_len as usize)]).ok_or_else(|| {
        anyhow!("Could not parse Ethernet packet (buffer size less than minimal)")
    })?;

    // We can report non-Ethernet packets, sanity check they look like one. We
    // could still get invalid ones, if the data at the right offset looks like
    // an ethernet packet; but what else can we do?
    if etype_str(eth.get_ethertype().0).is_none() {
        return Ok(());
    }

    if report_eth && raw.fake_eth == 0 {
        event.eth = Some(unmarshal_eth(&eth)?);
    }

    match eth.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(eth) = ArpPacket::new(eth.payload()) {
                event.arp = unmarshal_arp(&eth)?;
            };
        }
        EtherTypes::Ipv4 => {
            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                event.ip = Some(unmarshal_ipv4(&ip)?);
                unmarshal_l4(event, ip.get_next_level_protocol(), ip.payload())?;
            };
        }
        EtherTypes::Ipv6 => {
            if let Some(ip) = Ipv6Packet::new(eth.payload()) {
                event.ip = Some(unmarshal_ipv6(&ip)?);
                unmarshal_l4(event, ip.get_next_header(), ip.payload())?;
            };
        }
        // If we did not generate any data in the skb section, this means we do
        // not support yet the protocol used. At least provide the ethertype (we
        // already checked it looked valid).
        _ => {
            if event.eth.is_none() {
                event.eth = Some(unmarshal_eth(&eth)?);
            }
        }
    }

    Ok(())
}

fn unmarshal_l4(
    event: &mut SkbEvent,
    protocol: IpNextHeaderProtocol,
    payload: &[u8],
) -> Result<()> {
    match protocol {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(payload) {
                event.tcp = Some(unmarshal_tcp(&tcp)?);
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(payload) {
                event.udp = Some(unmarshal_udp(&udp)?);
            }
        }
        IpNextHeaderProtocols::Icmp => {
            if let Some(icmp) = IcmpPacket::new(payload) {
                event.icmp = Some(unmarshal_icmp(&icmp)?);
            }
        }
        IpNextHeaderProtocols::Icmpv6 => {
            if let Some(icmpv6) = Icmpv6Packet::new(payload) {
                event.icmpv6 = Some(unmarshal_icmpv6(&icmpv6)?);
            }
        }
        _ => (),
    }

    Ok(())
}

#[event_section_factory(FactoryId::Skb)]
#[derive(Default)]
pub(crate) struct SkbEventFactory {
    // Should we report the Ethernet header.
    pub(super) report_eth: bool,
}

impl RawEventSectionFactory for SkbEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut event = SkbEvent::default();

        for section in raw_sections.iter() {
            match section.header.data_type as u32 {
                SECTION_DEV => event.dev = unmarshal_dev(section)?,
                SECTION_NS => event.ns = Some(unmarshal_ns(section)?),
                SECTION_META => event.meta = Some(unmarshal_meta(section)?),
                SECTION_DATA_REF => event.data_ref = Some(unmarshal_data_ref(section)?),
                SECTION_GSO => event.gso = Some(unmarshal_gso(section)?),
                SECTION_PACKET => unmarshal_packet(&mut event, section, self.report_eth)?,
                x => bail!("Unknown data type ({x})"),
            }
        }

        Ok(Box::new(event))
    }
}

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use super::*;
    use crate::{benchmark::helpers::*, core::events::FactoryId};

    impl RawSectionBuilder for skb_netdev_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self {
                dev_name: [
                    b'e', b't', b'h', b'0', b'\0', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                ..Default::default()
            };
            build_raw_section(
                out,
                FactoryId::Skb as u8,
                SECTION_DEV as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }

    impl RawSectionBuilder for skb_netns_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self::default();
            build_raw_section(
                out,
                FactoryId::Skb as u8,
                SECTION_NS as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }

    impl RawSectionBuilder for skb_packet_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self {
                len: 66,
                capture_len: 66,
                packet: [
                    46, 137, 59, 254, 34, 122, 42, 186, 90, 193, 129, 79, 8, 0, 69, 0, 0, 52, 32,
                    32, 64, 0, 55, 6, 237, 160, 1, 1, 1, 1, 10, 0, 42, 2, 1, 187, 157, 12, 31, 149,
                    22, 86, 145, 251, 180, 241, 128, 17, 0, 8, 17, 72, 0, 0, 1, 1, 8, 10, 28, 109,
                    231, 120, 127, 134, 144, 92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                ..Default::default()
            };
            build_raw_section(
                out,
                FactoryId::Skb as u8,
                SECTION_PACKET as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }
}
