//! Rust<>BPF types definitions for the skb module. Fields are not translated in
//! the BPF part and can be represented in various orders, depending from where
//! they come from. Some handling might be needed in the unmarshalers.
//!
//! Please keep this file in sync with its BPF counterpart in bpf/skb_hook.bpf.c

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str,
};

use anyhow::Result;
use plain::Plain;

use super::*;
use crate::core::events::bpf::{parse_raw_section, BpfRawSection};

/// Valid raw event sections of the skb collector. We do not use an enum here as
/// they are difficult to work with for bitfields and C repr conversion.
pub(super) const SECTION_ETH: u64 = 0;
pub(super) const SECTION_IPV4: u64 = 1;
pub(super) const SECTION_IPV6: u64 = 2;
pub(super) const SECTION_TCP: u64 = 3;
pub(super) const SECTION_UDP: u64 = 4;
pub(super) const SECTION_ICMP: u64 = 5;
pub(super) const SECTION_DEV: u64 = 6;
pub(super) const SECTION_NS: u64 = 7;
pub(super) const SECTION_META: u64 = 8;
pub(super) const SECTION_DATA_REF: u64 = 9;

/// Global configuration passed down the BPF part.
#[repr(C, packed)]
pub(super) struct RawConfig {
    /// Bitfield of what to collect from skbs. Currently `1 << SECTION_x` is
    /// used to trigger retrieval of a given section.
    pub sections: u64,
}

/// Ethernet data retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct RawEthEvent {
    /// Source MAC address.
    src: [u8; 6],
    /// Destination MAC address.
    dst: [u8; 6],
    /// Ethertype. Stored in network order.
    etype: u16,
}
unsafe impl Plain for RawEthEvent {}

pub(super) fn unmarshal_eth(raw_section: &BpfRawSection) -> Result<SkbEthEvent> {
    let raw = parse_raw_section::<RawEthEvent>(raw_section)?;

    Ok(SkbEthEvent {
        etype: u16::from_be(raw.etype),
        src: format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            raw.src[0], raw.src[1], raw.src[2], raw.src[3], raw.src[4], raw.src[5],
        ),
        dst: format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            raw.dst[0], raw.dst[1], raw.dst[2], raw.dst[3], raw.dst[4], raw.dst[5],
        ),
    })
}

/// IPv4 data retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct RawIpv4Event {
    /// Source IP address. Stored in network order.
    src: u32,
    /// Destination IP address. Stored in network order.
    dst: u32,
    /// IP packet length in bytes. Stored in network order.
    len: u16,
    /// L4 protocol.
    protocol: u8,
}
unsafe impl Plain for RawIpv4Event {}

pub(super) fn unmarshal_ipv4(raw_section: &BpfRawSection) -> Result<SkbIpEvent> {
    let raw = parse_raw_section::<RawIpv4Event>(raw_section)?;

    let src = Ipv4Addr::from(u32::from_be(raw.src));
    let dst = Ipv4Addr::from(u32::from_be(raw.dst));

    Ok(SkbIpEvent {
        saddr: format!("{src}"),
        daddr: format!("{dst}"),
        version: 4,
        protocol: raw.protocol,
        len: u16::from_be(raw.len),
    })
}

/// IPv6 data retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct RawIpv6Event {
    /// Source IP address. Stored in network order.
    src: u128,
    /// Destination IP address. Stored in network order.
    dst: u128,
    /// IP packet length in bytes. Stored in network order.
    len: u16,
    /// L4 protocol.
    protocol: u8,
}
unsafe impl Plain for RawIpv6Event {}

pub(super) fn unmarshal_ipv6(raw_section: &BpfRawSection) -> Result<SkbIpEvent> {
    let raw = parse_raw_section::<RawIpv6Event>(raw_section)?;

    let src = Ipv6Addr::from(u128::from_be(raw.src));
    let dst = Ipv6Addr::from(u128::from_be(raw.dst));

    Ok(SkbIpEvent {
        saddr: format!("{src}"),
        daddr: format!("{dst}"),
        version: 6,
        protocol: raw.protocol,
        len: u16::from_be(raw.len),
    })
}

/// TCP data retrieved from skbs.
#[derive(Default)]
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
unsafe impl Plain for RawTcpEvent {}

pub(super) fn unmarshal_tcp(raw_section: &BpfRawSection) -> Result<SkbTcpEvent> {
    let raw = parse_raw_section::<RawTcpEvent>(raw_section)?;

    Ok(SkbTcpEvent {
        sport: u16::from_be(raw.sport),
        dport: u16::from_be(raw.dport),
        seq: u32::from_be(raw.seq),
        ack_seq: u32::from_be(raw.ack_seq),
        window: u16::from_be(raw.window),
        flags: raw.flags,
    })
}

/// UDP data retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct RawUdpEvent {
    /// Source port. Stored in network order.
    sport: u16,
    /// Destination port. Stored in network order.
    dport: u16,
    /// Lenght: length in bytes of the UDP header and UDP data. Stored in network order.
    len: u16,
}
unsafe impl Plain for RawUdpEvent {}

pub(super) fn unmarshal_udp(raw_section: &BpfRawSection) -> Result<SkbUdpEvent> {
    let raw = parse_raw_section::<RawUdpEvent>(raw_section)?;

    Ok(SkbUdpEvent {
        sport: u16::from_be(raw.sport),
        dport: u16::from_be(raw.dport),
        len: u16::from_be(raw.len),
    })
}

/// ICMP data retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct RawIcmpEvent {
    /// ICMP type.
    r#type: u8,
    /// ICMP sub-type.
    code: u8,
}
unsafe impl Plain for RawIcmpEvent {}

pub(super) fn unmarshal_icmp(raw_section: &BpfRawSection) -> Result<SkbIcmpEvent> {
    let raw = parse_raw_section::<RawIcmpEvent>(raw_section)?;

    Ok(SkbIcmpEvent {
        r#type: raw.r#type,
        code: raw.code,
    })
}

/// Net device information retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct RawDevEvent {
    /// Net device name.
    dev_name: [u8; 16],
    /// Net device index.
    ifindex: u32,
    /// Original ifindex the packet arrived on.
    iif: u32,
}
unsafe impl Plain for RawDevEvent {}

pub(super) fn unmarshal_dev(raw_section: &BpfRawSection) -> Result<SkbDevEvent> {
    let raw = parse_raw_section::<RawDevEvent>(raw_section)?;
    let mut event = SkbDevEvent::default();

    let dev_name = str::from_utf8(&raw.dev_name)?.trim_end_matches(char::from(0));
    event.name = dev_name.to_string();
    event.ifindex = raw.ifindex;

    if raw.iif > 0 {
        event.rx_ifindex = Some(raw.iif);
    }

    Ok(event)
}

/// Net namespace information retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct RawNsEvent {
    /// Net namespace id.
    netns: u32,
}
unsafe impl Plain for RawNsEvent {}

pub(super) fn unmarshal_ns(raw_section: &BpfRawSection) -> Result<SkbNsEvent> {
    let raw = parse_raw_section::<RawNsEvent>(raw_section)?;

    Ok(SkbNsEvent { netns: raw.netns })
}

/// Skb metadata & related.
#[derive(Default)]
#[repr(C, packed)]
struct RawMetaEvent {
    len: u32,
    data_len: u32,
    hash: u32,
    csum: u32,
    priority: u32,
}
unsafe impl Plain for RawMetaEvent {}

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
#[derive(Default)]
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
unsafe impl Plain for RawDataRefEvent {}

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
