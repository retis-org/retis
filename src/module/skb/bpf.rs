//! Rust<>BPF types definitions for the skb module. Fields are not translated in
//! the BPF part and can be represented in various orders, depending from where
//! they come from. Some handling might be needed in the unmarshalers.
//!
//! Please keep this file in sync with its BPF counterpart in bpf/skb_hook.bpf.c

use std::str;

use anyhow::{anyhow, bail, Result};
use pnet::packet::{ethernet::*, ipv4::*, ipv6::*, Packet};

use super::*;
use crate::core::{
    events::bpf::{parse_raw_section, BpfRawSection},
    helpers,
};

/// Valid raw event sections of the skb collector. We do not use an enum here as
/// they are difficult to work with for bitfields and C repr conversion.
pub(super) const SECTION_ARP: u64 = 1;
pub(super) const SECTION_TCP: u64 = 4;
pub(super) const SECTION_UDP: u64 = 5;
pub(super) const SECTION_ICMP: u64 = 6;
pub(super) const SECTION_DEV: u64 = 7;
pub(super) const SECTION_NS: u64 = 8;
pub(super) const SECTION_META: u64 = 9;
pub(super) const SECTION_DATA_REF: u64 = 10;
pub(super) const SECTION_PACKET: u64 = 11;
pub(super) const SECTION_GSO: u64 = 12;

/// Global configuration passed down the BPF part.
#[repr(C, packed)]
pub(super) struct RawConfig {
    /// Bitfield of what to collect from skbs. Currently `1 << SECTION_x` is
    /// used to trigger retrieval of a given section.
    pub sections: u64,
}

pub(super) fn unmarshal_eth(eth: &EthernetPacket) -> Result<SkbEthEvent> {
    Ok(SkbEthEvent {
        etype: eth.get_ethertype().0,
        src: helpers::net::parse_eth_addr(&eth.get_source().octets())?,
        dst: helpers::net::parse_eth_addr(&eth.get_destination().octets())?,
    })
}

/// ARP data retrieved from skbs.
#[repr(C, packed)]
struct RawArpEvent {
    /// Operation. Stored in network order.
    operation: u16,
    /// Sender hardware address.
    sha: [u8; 6],
    /// Sender protocol address.
    spa: u32,
    /// Target hardware address.
    tha: [u8; 6],
    /// Target protocol address.
    tpa: u32,
}

pub(super) fn unmarshal_arp(raw_section: &BpfRawSection) -> Result<SkbArpEvent> {
    let raw = parse_raw_section::<RawArpEvent>(raw_section)?;

    let operation = match u16::from_be(raw.operation) {
        1 => ArpOperation::Request,
        2 => ArpOperation::Reply,
        _ => bail!("Invalid ARP operation type"),
    };

    Ok(SkbArpEvent {
        operation,
        sha: helpers::net::parse_eth_addr(&raw.sha)?,
        spa: helpers::net::parse_ipv4_addr(u32::from_be(raw.spa))?,
        tha: helpers::net::parse_eth_addr(&raw.tha)?,
        tpa: helpers::net::parse_ipv4_addr(u32::from_be(raw.tpa))?,
    })
}

pub(super) fn unmarshal_ipv4(ip: &Ipv4Packet) -> Result<SkbIpEvent> {
    Ok(SkbIpEvent {
        saddr: helpers::net::parse_ipv4_addr(u32::from(ip.get_source()))?,
        daddr: helpers::net::parse_ipv4_addr(u32::from(ip.get_destination()))?,
        version: SkbIpVersion::V4(SkbIpv4Event {
            tos: ip.get_dscp(),
            flags: ip.get_flags(),
            id: ip.get_identification(),
            offset: ip.get_fragment_offset(),
        }),
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
        version: SkbIpVersion::V6(SkbIpv6Event {
            flow_label: ip.get_flow_label(),
        }),
        protocol: ip.get_next_header().0,
        len: ip.get_payload_length(),
        ttl: ip.get_hop_limit(),
        ecn: ip.get_traffic_class() & 0x3,
    })
}

/// TCP data retrieved from skbs.
#[repr(C, packed)]
struct RawTcpEvent {
    /// Source port. Stored in network order.
    sport: u16,
    /// Destination port. Stored in network order.
    dport: u16,
    /// Sequence number. Stored in network order.
    seq: u32,
    /// Ack sequence number. Stored in network order.
    ack_seq: u32,
    /// TCP window. Stored in network order.
    window: u16,
    /// TCP flags (from low to high): fin, syn, rst, psh, ack, urg, ece, cwr.
    flags: u8,
    /// TCP data offset: size of the TCP header in 32-bit words.
    doff: u8,
}

pub(super) fn unmarshal_tcp(raw_section: &BpfRawSection) -> Result<SkbTcpEvent> {
    let raw = parse_raw_section::<RawTcpEvent>(raw_section)?;

    Ok(SkbTcpEvent {
        sport: u16::from_be(raw.sport),
        dport: u16::from_be(raw.dport),
        seq: u32::from_be(raw.seq),
        ack_seq: u32::from_be(raw.ack_seq),
        window: u16::from_be(raw.window),
        doff: raw.doff,
        flags: raw.flags,
    })
}

/// UDP data retrieved from skbs.
#[repr(C, packed)]
struct RawUdpEvent {
    /// Source port. Stored in network order.
    sport: u16,
    /// Destination port. Stored in network order.
    dport: u16,
    /// Lenght: length in bytes of the UDP header and UDP data. Stored in network order.
    len: u16,
}

pub(super) fn unmarshal_udp(raw_section: &BpfRawSection) -> Result<SkbUdpEvent> {
    let raw = parse_raw_section::<RawUdpEvent>(raw_section)?;

    Ok(SkbUdpEvent {
        sport: u16::from_be(raw.sport),
        dport: u16::from_be(raw.dport),
        len: u16::from_be(raw.len),
    })
}

/// ICMP data retrieved from skbs.
#[repr(C, packed)]
struct RawIcmpEvent {
    /// ICMP type.
    r#type: u8,
    /// ICMP sub-type.
    code: u8,
}

pub(super) fn unmarshal_icmp(raw_section: &BpfRawSection) -> Result<SkbIcmpEvent> {
    let raw = parse_raw_section::<RawIcmpEvent>(raw_section)?;

    Ok(SkbIcmpEvent {
        r#type: raw.r#type,
        code: raw.code,
    })
}

/// Net device information retrieved from skbs.
#[repr(C, packed)]
struct RawDevEvent {
    /// Net device name.
    dev_name: [u8; 16],
    /// Net device index.
    ifindex: u32,
    /// Original ifindex the packet arrived on.
    iif: u32,
}

/// Unmarshal net device info. Can return Ok(None) in case the info does not
/// look like it's genuine (see below).
pub(super) fn unmarshal_dev(raw_section: &BpfRawSection) -> Result<Option<SkbDevEvent>> {
    let raw = parse_raw_section::<RawDevEvent>(raw_section)?;

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

/// Net namespace information retrieved from skbs.
#[repr(C, packed)]
struct RawNsEvent {
    /// Net namespace id.
    netns: u32,
}

pub(super) fn unmarshal_ns(raw_section: &BpfRawSection) -> Result<SkbNsEvent> {
    let raw = parse_raw_section::<RawNsEvent>(raw_section)?;

    Ok(SkbNsEvent { netns: raw.netns })
}

/// Skb metadata & related.
#[repr(C, packed)]
struct RawMetaEvent {
    len: u32,
    data_len: u32,
    hash: u32,
    ip_summed: u8,
    csum: u32,
    csum_level: u8,
    priority: u32,
}

pub(super) fn unmarshal_meta(raw_section: &BpfRawSection) -> Result<SkbMetaEvent> {
    let raw = parse_raw_section::<RawMetaEvent>(raw_section)?;

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

/// Data & refcount information retrieved from skbs.
#[repr(C, packed)]
struct RawDataRefEvent {
    nohdr: u8,
    /// Is the skb a clone?
    cloned: u8,
    /// Is the skb a fast clone?
    fclone: u8,
    /// Users count.
    users: u8,
    /// Data refcount.
    dataref: u8,
}

pub(super) fn unmarshal_data_ref(raw_section: &BpfRawSection) -> Result<SkbDataRefEvent> {
    let raw = parse_raw_section::<RawDataRefEvent>(raw_section)?;

    Ok(SkbDataRefEvent {
        nohdr: raw.nohdr == 1,
        cloned: raw.cloned == 1,
        fclone: raw.fclone,
        users: raw.users,
        dataref: raw.dataref,
    })
}

/// GSO information.
#[repr(C, packed)]
struct RawGsoEvent {
    flags: u8,
    nr_frags: u8,
    gso_size: u32,
    gso_segs: u32,
    gso_type: u32,
}

pub(super) fn unmarshal_gso(raw_section: &BpfRawSection) -> Result<SkbGsoEvent> {
    let raw = parse_raw_section::<RawGsoEvent>(raw_section)?;

    Ok(SkbGsoEvent {
        flags: raw.flags,
        frags: raw.nr_frags,
        size: raw.gso_size,
        segs: raw.gso_segs,
        r#type: raw.gso_type,
    })
}

/// Raw packet and related metadata extracted from skbs.
#[repr(C, packed)]
pub(super) struct RawPacketEvent {
    /// Length of the packet.
    len: u32,
    /// Lenght of the capture. <= len.
    capture_len: u32,
    /// Raw packet data.
    packet: [u8; 255],
}

pub(super) fn unmarshal_packet(event: &mut SkbEvent, raw_section: &BpfRawSection) -> Result<()> {
    let raw = parse_raw_section::<RawPacketEvent>(raw_section)?;

    // First add the raw packet part in the event.
    event.packet = Some(SkbPacketEvent {
        len: raw.len,
        capture_len: raw.capture_len,
        packet: raw.packet[..(raw.capture_len as usize)].to_vec(),
    });

    // Then start parsing the raw packet to generate other sections.
    let eth = EthernetPacket::new(&raw.packet[..(raw.capture_len as usize)]).ok_or_else(|| {
        anyhow!("Could not parse Ethernet packet (buffer size less than minimal)")
    })?;
    event.eth = Some(unmarshal_eth(&eth)?);

    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            event.ip = Some(unmarshal_ipv4(
                &Ipv4Packet::new(eth.payload())
                    .ok_or_else(|| anyhow!("Could not parse IPv4 packet"))?,
            )?)
        }
        EtherTypes::Ipv6 => {
            event.ip = Some(unmarshal_ipv6(
                &Ipv6Packet::new(eth.payload())
                    .ok_or_else(|| anyhow!("Could not parse IPv6 packet"))?,
            )?)
        }
        _ => return Ok(()),
    }

    Ok(())
}
