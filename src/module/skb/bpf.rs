//! Rust<>BPF types definitions for the skb module. Fields are not translated in
//! the BPF part and can be represented in various orders, depending from where
//! they come from. Some handling might be needed in the unmarshalers.
//!
//! Please keep this file in sync with its BPF counterpart in bpf/skb_hook.bpf.c

use std::net::{Ipv4Addr, Ipv6Addr};

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
