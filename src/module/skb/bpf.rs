//! Rust<>BPF types definitions for the skb module. Fields are not translated in
//! the BPF part and can be represented in various orders, depending from where
//! they come from. Some handling might be needed in the unmarshalers.
//!
//! Please keep this file in sync with its BPF counterpart in bpf/skb_hook.bpf.c

use std::{net::Ipv6Addr, str};

use anyhow::{bail, Result};

use super::*;
use crate::core::{
    events::bpf::{parse_raw_section, BpfRawSection},
    helpers,
};

/// Valid raw event sections of the skb collector. We do not use an enum here as
/// they are difficult to work with for bitfields and C repr conversion.
pub(super) const SECTION_ETH: u64 = 0;
pub(super) const SECTION_ARP: u64 = 1;
pub(super) const SECTION_IPV4: u64 = 2;
pub(super) const SECTION_IPV6: u64 = 3;
pub(super) const SECTION_TCP: u64 = 4;
pub(super) const SECTION_UDP: u64 = 5;
pub(super) const SECTION_ICMP: u64 = 6;
pub(super) const SECTION_DEV: u64 = 7;
pub(super) const SECTION_NS: u64 = 8;
pub(super) const SECTION_META: u64 = 9;
pub(super) const SECTION_DATA_REF: u64 = 10;
pub(super) const SECTION_PACKET: u64 = 11;

/// Global configuration passed down the BPF part.
#[repr(C, packed)]
pub(super) struct RawConfig {
    /// Bitfield of what to collect from skbs. Currently `1 << SECTION_x` is
    /// used to trigger retrieval of a given section.
    pub sections: u64,
}

/// Ethernet data retrieved from skbs.
#[repr(C, packed)]
struct RawEthEvent {
    /// Source MAC address.
    src: [u8; 6],
    /// Destination MAC address.
    dst: [u8; 6],
    /// Ethertype. Stored in network order.
    etype: u16,
}

pub(super) fn unmarshal_eth(raw_section: &BpfRawSection) -> Result<SkbEthEvent> {
    let raw = parse_raw_section::<RawEthEvent>(raw_section)?;

    Ok(SkbEthEvent {
        etype: u16::from_be(raw.etype),
        src: helpers::net::parse_eth_addr(&raw.src)?,
        dst: helpers::net::parse_eth_addr(&raw.dst)?,
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

/// IPv4 data retrieved from skbs.
#[repr(C, packed)]
struct RawIpv4Event {
    /// Source IP address. Stored in network order.
    src: u32,
    /// Destination IP address. Stored in network order.
    dst: u32,
    /// IP packet length in bytes. Stored in network order.
    len: u16,
    /// Identification. Stored in network order.
    id: u16,
    /// L4 protocol.
    protocol: u8,
    /// Time to live.
    ttl: u8,
    /// Type of service.
    tos: u8,
    /// ECN bits.
    ecn: u8,
    /// Fragment offset. Stored in network order.
    offset: u16,
    /// Flags (CE, DF, MF).
    flags: u8,
}

pub(super) fn unmarshal_ipv4(raw_section: &BpfRawSection) -> Result<SkbIpEvent> {
    let raw = parse_raw_section::<RawIpv4Event>(raw_section)?;

    Ok(SkbIpEvent {
        saddr: helpers::net::parse_ipv4_addr(u32::from_be(raw.src))?,
        daddr: helpers::net::parse_ipv4_addr(u32::from_be(raw.dst))?,
        version: SkbIpVersion::V4(SkbIpv4Event {
            tos: raw.tos,
            flags: raw.flags,
            id: u16::from_be(raw.id),
            offset: u16::from_be(raw.offset),
        }),
        protocol: raw.protocol,
        len: u16::from_be(raw.len),
        ttl: raw.ttl,
        ecn: raw.ecn,
    })
}

/// IPv6 data retrieved from skbs.
#[repr(C, packed)]
struct RawIpv6Event {
    /// Source IP address. Stored in network order.
    src: u128,
    /// Destination IP address. Stored in network order.
    dst: u128,
    /// Flow label.
    flow_label: u32,
    /// IP packet length in bytes. Stored in network order.
    len: u16,
    /// L4 protocol.
    protocol: u8,
    /// TTL.
    ttl: u8,
    /// ECN bits.
    ecn: u8,
}

pub(super) fn unmarshal_ipv6(raw_section: &BpfRawSection) -> Result<SkbIpEvent> {
    let raw = parse_raw_section::<RawIpv6Event>(raw_section)?;

    Ok(SkbIpEvent {
        saddr: Ipv6Addr::from(u128::from_be(raw.src)).to_string(),
        daddr: Ipv6Addr::from(u128::from_be(raw.dst)).to_string(),
        version: SkbIpVersion::V6(SkbIpv6Event {
            flow_label: raw.flow_label,
        }),
        protocol: raw.protocol,
        len: u16::from_be(raw.len),
        ttl: raw.ttl,
        ecn: raw.ecn,
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
    csum: u32,
    priority: u32,
}

pub(super) fn unmarshal_meta(raw_section: &BpfRawSection) -> Result<SkbMetaEvent> {
    let raw = parse_raw_section::<RawMetaEvent>(raw_section)?;

    Ok(SkbMetaEvent {
        len: raw.len,
        data_len: raw.data_len,
        hash: raw.hash,
        csum: raw.csum,
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

/// Raw packet and related metadata extracted from skbs.
#[repr(C, packed)]
pub(super) struct RawPacketEvent {
    /// Length of the packet.
    len: u32,
    /// Lenght of the capture. <= len.
    capture_len: u32,
    /// Raw packet data.
    packet: [u8; 256],
}

pub(super) fn unmarshal_packet(raw_section: &BpfRawSection) -> Result<SkbPacketEvent> {
    let raw = parse_raw_section::<RawPacketEvent>(raw_section)?;

    Ok(SkbPacketEvent {
        len: raw.len,
        capture_len: raw.capture_len,
        packet: raw.packet[..(raw.capture_len as usize)].to_vec(),
    })
}
