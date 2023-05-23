use anyhow::{bail, Result};

use super::bpf::*;
use crate::{
    core::events::{bpf::BpfRawSection, *},
    event_section, event_section_factory,
    EventSectionDisplay,
};

/// Skb event section.
#[event_section]
#[derive(EventSectionDisplay)]
pub(crate) struct SkbEvent {
    eth: Option<SkbEthEvent>,
    ip: Option<SkbIpEvent>,
    tcp: Option<SkbTcpEvent>,
    udp: Option<SkbUdpEvent>,
    icmp: Option<SkbIcmpEvent>,
    dev: Option<SkbDevEvent>,
    ns: Option<SkbNsEvent>,
    meta: Option<SkbMetaEvent>,
    data_ref: Option<SkbDataRefEvent>,
}

/// Ethernet fields.
#[derive(Debug, EventSectionDisplay, serde::Deserialize, serde::Serialize)]
pub(crate) struct SkbEthEvent {
    /// Ethertype.
    pub(crate) etype: u16,
    /// Source MAC address.
    pub(crate) src: String,
    /// Destination MAC address.
    pub(crate) dst: String,
}

/// IPv4/IPv6 fields.
#[derive(Debug, EventSectionDisplay, serde::Deserialize, serde::Serialize)]
pub(crate) struct SkbIpEvent {
    /// Source IP address.
    pub(crate) saddr: String,
    /// Destination IP address.
    pub(crate) daddr: String,
    /// IP version: 4 or 6.
    pub(crate) version: u8,
    /// L4 protocol, from IPv4 "protocol" field or IPv6 "next header" one.
    pub(crate) protocol: u8,
    /// "total len" from the IPv4 header or "payload length" from the IPv6 one.
    pub(crate) len: u16,
}

/// TCP fields.
#[derive(Debug, EventSectionDisplay, serde::Deserialize, serde::Serialize)]
pub(crate) struct SkbTcpEvent {
    /// Source port.
    pub(crate) sport: u16,
    /// Destination port.
    pub(crate) dport: u16,
    pub(crate) seq: u32,
    pub(crate) ack_seq: u32,
    pub(crate) window: u16,
    /// Bitfield of TCP flags as defined in `struct tcphdr` in the kernel.
    pub(crate) flags: u8,
}

/// UDP fields.
#[derive(Debug, EventSectionDisplay, serde::Deserialize, serde::Serialize)]
pub(crate) struct SkbUdpEvent {
    /// Source port.
    pub(crate) sport: u16,
    /// Destination port.
    pub(crate) dport: u16,
    /// Length from the UDP header.
    pub(crate) len: u16,
}

/// ICMP fields.
#[derive(Debug, EventSectionDisplay, serde::Deserialize, serde::Serialize)]
pub(crate) struct SkbIcmpEvent {
    pub(crate) r#type: u8,
    pub(crate) code: u8,
}

/// Network device fields.
#[serde_with::skip_serializing_none]
#[derive(Debug, Default, EventSectionDisplay, serde::Deserialize, serde::Serialize)]
pub(crate) struct SkbDevEvent {
    /// Net device name associated with the packet, from `skb->dev->name`.
    pub(crate) name: String,
    /// Net device ifindex associated with the packet, from `skb->dev->ifindex`.
    pub(crate) ifindex: u32,
    /// Index if the net device the packet arrived on, from `skb->skb_iif`.
    pub(crate) rx_ifindex: Option<u32>,
}

/// Network namespace fields.
#[derive(Debug, EventSectionDisplay, serde::Deserialize, serde::Serialize)]
pub(crate) struct SkbNsEvent {
    /// Id of the network namespace associated with the packet, from the device
    /// or the associated socket (in that order).
    pub(crate) netns: u32,
}

/// Skb metadata & releated fields.
#[derive(Debug, EventSectionDisplay, serde::Deserialize, serde::Serialize)]
pub(crate) struct SkbMetaEvent {
    /// Total number of bytes in the packet.
    pub(crate) len: u32,
    /// Total number of bytes in the page buffer area.
    pub(crate) data_len: u32,
    /// Packet hash (!= hash of the packet data).
    pub(crate) hash: u32,
    /// Packet checksum.
    pub(crate) csum: u32,
    /// QoS priority.
    pub(crate) priority: u32,
}

/// Skb data & refcnt fields.
#[derive(Debug, EventSectionDisplay, serde::Deserialize, serde::Serialize)]
pub(crate) struct SkbDataRefEvent {
    /// Payload reference only.
    pub(crate) nohdr: bool,
    /// Is the skb a clone?
    pub(crate) cloned: bool,
    /// Skb fast clone information.
    pub(crate) fclone: u8,
    /// Users count.
    pub(crate) users: u8,
    /// Data refcount.
    pub(crate) dataref: u8,
}

#[derive(Default)]
#[event_section_factory(SkbEvent)]
pub(crate) struct SkbEventFactory {}

impl RawEventSectionFactory for SkbEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut event = SkbEvent::default();

        for section in raw_sections.iter() {
            match section.header.data_type as u64 {
                SECTION_ETH => event.eth = Some(unmarshal_eth(section)?),
                SECTION_IPV4 => event.ip = Some(unmarshal_ipv4(section)?),
                SECTION_IPV6 => event.ip = Some(unmarshal_ipv6(section)?),
                SECTION_TCP => event.tcp = Some(unmarshal_tcp(section)?),
                SECTION_UDP => event.udp = Some(unmarshal_udp(section)?),
                SECTION_ICMP => event.icmp = Some(unmarshal_icmp(section)?),
                SECTION_DEV => event.dev = Some(unmarshal_dev(section)?),
                SECTION_NS => event.ns = Some(unmarshal_ns(section)?),
                SECTION_META => event.meta = Some(unmarshal_meta(section)?),
                SECTION_DATA_REF => event.data_ref = Some(unmarshal_data_ref(section)?),
                _ => bail!("Unknown data type"),
            }
        }

        Ok(Box::new(event))
    }
}
