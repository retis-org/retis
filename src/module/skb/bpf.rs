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

use super::SkbEvent;
use crate::core::events::bpf::{parse_raw_section, BpfRawSection};

/// Valid raw event sections of the skb collector. We do not use an enum here as
/// they are difficult to work with for bitfields and C repr conversion.
pub(super) const SECTION_L2: u64 = 0;
pub(super) const SECTION_IPV4: u64 = 1;
pub(super) const SECTION_IPV6: u64 = 2;
pub(super) const SECTION_TCP: u64 = 3;
pub(super) const SECTION_UDP: u64 = 4;
pub(super) const SECTION_ICMP: u64 = 5;
pub(super) const SECTION_DEV: u64 = 6;
pub(super) const SECTION_NS: u64 = 7;
pub(super) const SECTION_DATA_REF: u64 = 8;

/// Global configuration passed down the BPF part.
#[repr(C, packed)]
pub(super) struct SkbConfig {
    /// Bitfield of what to collect from skbs. Currently `1 << SECTION_x` is
    /// used to trigger retrieval of a given section.
    pub sections: u64,
}

/// L2 data retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbL2Event {
    /// Source MAC address.
    src: [u8; 6],
    /// Destination MAC address.
    dst: [u8; 6],
    /// Ethertype. Stored in network order.
    etype: u16,
}
unsafe impl Plain for SkbL2Event {}

pub(super) fn unmarshal_l2(raw_section: &BpfRawSection, event: &mut SkbEvent) -> Result<()> {
    let raw = parse_raw_section::<SkbL2Event>(raw_section)?;

    event.etype = Some(u16::from_be(raw.etype));
    event.src = Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        raw.src[0], raw.src[1], raw.src[2], raw.src[3], raw.src[4], raw.src[5],
    ));
    event.dst = Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        raw.dst[0], raw.dst[1], raw.dst[2], raw.dst[3], raw.dst[4], raw.dst[5],
    ));

    Ok(())
}

/// IPv4 data retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbIpv4Event {
    /// Source IP address. Stored in network order.
    src: u32,
    /// Destination IP address. Stored in network order.
    dst: u32,
    /// IP packet length in bytes. Stored in network order.
    len: u16,
    /// L4 protocol.
    protocol: u8,
}
unsafe impl Plain for SkbIpv4Event {}

pub(super) fn unmarshal_ipv4(raw_section: &BpfRawSection, event: &mut SkbEvent) -> Result<()> {
    let raw = parse_raw_section::<SkbIpv4Event>(raw_section)?;

    let src = Ipv4Addr::from(u32::from_be(raw.src));
    event.saddr = Some(format!("{src}"));
    let dst = Ipv4Addr::from(u32::from_be(raw.dst));
    event.daddr = Some(format!("{dst}"));

    event.ip_version = Some(4);
    event.l3_len = Some(u16::from_be(raw.len));
    event.protocol = Some(raw.protocol);

    Ok(())
}

/// IPv6 data retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbIpv6Event {
    /// Source IP address. Stored in network order.
    src: u128,
    /// Destination IP address. Stored in network order.
    dst: u128,
    /// IP packet length in bytes. Stored in network order.
    len: u16,
    /// L4 protocol.
    protocol: u8,
}
unsafe impl Plain for SkbIpv6Event {}

pub(super) fn unmarshal_ipv6(raw_section: &BpfRawSection, event: &mut SkbEvent) -> Result<()> {
    let raw = parse_raw_section::<SkbIpv6Event>(raw_section)?;

    let src = Ipv6Addr::from(u128::from_be(raw.src));
    event.saddr = Some(format!("{src}"));
    let dst = Ipv6Addr::from(u128::from_be(raw.dst));
    event.daddr = Some(format!("{dst}"));

    event.ip_version = Some(6);
    event.l3_len = Some(u16::from_be(raw.len));
    event.protocol = Some(raw.protocol);

    Ok(())
}

/// TCP data retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbTcpEvent {
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
unsafe impl Plain for SkbTcpEvent {}

pub(super) fn unmarshal_tcp(raw_section: &BpfRawSection, event: &mut SkbEvent) -> Result<()> {
    let raw = parse_raw_section::<SkbTcpEvent>(raw_section)?;

    event.sport = Some(u16::from_be(raw.sport));
    event.dport = Some(u16::from_be(raw.dport));
    event.tcp_seq = Some(u32::from_be(raw.seq));
    event.tcp_ack_seq = Some(u32::from_be(raw.ack_seq));
    event.tcp_window = Some(u16::from_be(raw.window));
    event.tcp_flags = Some(raw.flags);

    Ok(())
}

/// UDP data retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbUdpEvent {
    /// Source port. Stored in network order.
    sport: u16,
    /// Destination port. Stored in network order.
    dport: u16,
    /// Lenght: length in bytes of the UDP header and UDP data. Stored in network order.
    len: u16,
}
unsafe impl Plain for SkbUdpEvent {}

pub(super) fn unmarshal_udp(raw_section: &BpfRawSection, event: &mut SkbEvent) -> Result<()> {
    let raw = parse_raw_section::<SkbUdpEvent>(raw_section)?;

    event.sport = Some(u16::from_be(raw.sport));
    event.dport = Some(u16::from_be(raw.dport));
    event.udp_len = Some(u16::from_be(raw.len));

    Ok(())
}

/// ICMP data retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbIcmpEvent {
    /// ICMP type.
    r#type: u8,
    /// ICMP sub-type.
    code: u8,
}
unsafe impl Plain for SkbIcmpEvent {}

pub(super) fn unmarshal_icmp(raw_section: &BpfRawSection, event: &mut SkbEvent) -> Result<()> {
    let raw = parse_raw_section::<SkbIcmpEvent>(raw_section)?;

    event.icmp_type = Some(raw.r#type);
    event.icmp_code = Some(raw.code);

    Ok(())
}

/// Net device information retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbDevEvent {
    /// Net device name.
    dev_name: [u8; 16],
    /// Net device index.
    ifindex: u32,
    /// Original ifindex the packet arrived on.
    iif: u32,
}
unsafe impl Plain for SkbDevEvent {}

pub(super) fn unmarshal_dev(raw_section: &BpfRawSection, event: &mut SkbEvent) -> Result<()> {
    let raw = parse_raw_section::<SkbDevEvent>(raw_section)?;

    let dev_name = str::from_utf8(&raw.dev_name)?.trim_end_matches(char::from(0));
    if !dev_name.is_empty() {
        event.dev_name = Some(dev_name.to_string());
    }

    if raw.ifindex > 0 {
        event.ifindex = Some(raw.ifindex);
    }

    if raw.iif > 0 {
        event.rx_ifindex = Some(raw.iif);
    }

    Ok(())
}

/// Net namespace information retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbNsEvent {
    /// Net namespace id.
    netns: u32,
}
unsafe impl Plain for SkbNsEvent {}

pub(super) fn unmarshal_ns(raw_section: &BpfRawSection, event: &mut SkbEvent) -> Result<()> {
    let raw = parse_raw_section::<SkbNsEvent>(raw_section)?;
    event.netns = Some(raw.netns);
    Ok(())
}

/// Data & refcount information retrieved from skbs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbDataRefEvent {
    /// Is the skb a clone?
    cloned: u8,
    /// Is the skb a fast clone?
    fclone: u8,
    /// Users count.
    users: u8,
    /// Data refcount.
    dataref: u8,
}
unsafe impl Plain for SkbDataRefEvent {}

pub(super) fn unmarshal_data_ref(raw_section: &BpfRawSection, event: &mut SkbEvent) -> Result<()> {
    let raw = parse_raw_section::<SkbDataRefEvent>(raw_section)?;

    event.cloned = Some(raw.cloned == 1);
    event.fclone = Some(raw.fclone == 1);
    event.users = Some(raw.users);
    event.dataref = Some(raw.dataref);

    Ok(())
}
