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

use crate::{
    core::events::{
        bpf::{parse_raw_section, BpfRawSection},
        EventField,
    },
    event_field,
};

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

pub(super) fn unmarshal_l2(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_raw_section::<SkbL2Event>(raw_section)?;

    fields.push(event_field!("etype", u16::from_be(event.etype)));
    fields.push(event_field!(
        "src",
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            event.src[0], event.src[1], event.src[2], event.src[3], event.src[4], event.src[5],
        )
    ));
    fields.push(event_field!(
        "dst",
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            event.dst[0], event.dst[1], event.dst[2], event.dst[3], event.dst[4], event.dst[5],
        )
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

pub(super) fn unmarshal_ipv4(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_raw_section::<SkbIpv4Event>(raw_section)?;

    let src = Ipv4Addr::from(u32::from_be(event.src));
    fields.push(event_field!("saddr", format!("{src}")));
    let dst = Ipv4Addr::from(u32::from_be(event.dst));
    fields.push(event_field!("daddr", format!("{dst}")));

    fields.push(event_field!("ip_version", 4));
    fields.push(event_field!("l3_len", u16::from_be(event.len)));
    fields.push(event_field!("protocol", event.protocol));

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

pub(super) fn unmarshal_ipv6(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_raw_section::<SkbIpv6Event>(raw_section)?;

    let src = Ipv6Addr::from(u128::from_be(event.src));
    fields.push(event_field!("saddr", format!("{src}")));
    let dst = Ipv6Addr::from(u128::from_be(event.dst));
    fields.push(event_field!("daddr", format!("{dst}")));

    fields.push(event_field!("ip_version", 6));
    fields.push(event_field!("l3_len", u16::from_be(event.len)));
    fields.push(event_field!("protocol", event.protocol));

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

pub(super) fn unmarshal_tcp(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_raw_section::<SkbTcpEvent>(raw_section)?;

    fields.push(event_field!("sport", u16::from_be(event.sport)));
    fields.push(event_field!("dport", u16::from_be(event.dport)));
    fields.push(event_field!("tcp_seq", u32::from_be(event.seq)));
    fields.push(event_field!("tcp_ack_seq", u32::from_be(event.ack_seq)));
    fields.push(event_field!("tcp_window", u16::from_be(event.window)));
    fields.push(event_field!("tcp_flags", event.flags));

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

pub(super) fn unmarshal_udp(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_raw_section::<SkbUdpEvent>(raw_section)?;

    fields.push(event_field!("sport", u16::from_be(event.sport)));
    fields.push(event_field!("dport", u16::from_be(event.dport)));
    fields.push(event_field!("udp_len", u16::from_be(event.len)));

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

pub(super) fn unmarshal_icmp(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_raw_section::<SkbIcmpEvent>(raw_section)?;

    fields.push(event_field!("icmp_type", event.r#type));
    fields.push(event_field!("icmp_code", event.code));

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

pub(super) fn unmarshal_dev(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_raw_section::<SkbDevEvent>(raw_section)?;

    let dev_name = str::from_utf8(&event.dev_name)?.trim_end_matches(char::from(0));
    if !dev_name.is_empty() {
        fields.push(event_field!("dev_name", dev_name.to_string()));
    }

    if event.ifindex > 0 {
        fields.push(event_field!("ifindex", event.ifindex));
    }
    if event.iif > 0 {
        fields.push(event_field!("rx_ifindex", event.iif));
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

pub(super) fn unmarshal_ns(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_raw_section::<SkbNsEvent>(raw_section)?;
    fields.push(event_field!("netns", event.netns));
    Ok(())
}
