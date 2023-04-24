use anyhow::{bail, Result};

use super::bpf::*;
use crate::{
    core::events::{bpf::BpfRawSection, *},
    event_section, event_section_factory,
};

/// Skb event section
/// TODO: unflatten?
#[event_section]
pub(crate) struct SkbEvent {
    // L2 fields
    /// Ethertype.
    pub(crate) etype: Option<u16>,
    /// Source MAC address.
    pub(crate) src: Option<String>,
    /// Destination MAC address.
    pub(crate) dst: Option<String>,
    // IPv4 & IPv6 fields
    /// Source IP address.
    pub(crate) saddr: Option<String>,
    /// Destination IP address.
    pub(crate) daddr: Option<String>,
    /// IP version: 4 or 6.
    pub(crate) ip_version: Option<u8>,
    /// "total len" from the IPv4 header or "payload length" from the IPv6 one.
    pub(crate) l3_len: Option<u16>,
    /// L4 protocol, from IPv4 "protocol" field or IPv6 "next header" one.
    pub(crate) protocol: Option<u8>,
    // TCP & UDP fields
    /// Source port.
    pub(crate) sport: Option<u16>,
    /// Destination port.
    pub(crate) dport: Option<u16>,
    // TCP fields
    pub(crate) tcp_seq: Option<u32>,
    pub(crate) tcp_ack_seq: Option<u32>,
    pub(crate) tcp_window: Option<u16>,
    /// Bitfield of TCP flags as defined in `struct tcphdr` in the kernel.
    pub(crate) tcp_flags: Option<u8>,
    // UDP fields
    /// Length from the UDP header.
    pub(crate) udp_len: Option<u16>,
    // ICMP fields
    pub(crate) icmp_type: Option<u8>,
    pub(crate) icmp_code: Option<u8>,
    // Net device fields
    /// Net device name associated with the packet, from `skb->dev->name`.
    pub(crate) dev_name: Option<String>,
    /// Net device ifindex associated with the packet, from `skb->dev->ifindex`.
    pub(crate) ifindex: Option<u32>,
    /// Index if the net device the packet arrived on, from `skb->skb_iif`.
    pub(crate) rx_ifindex: Option<u32>,
    // Netns fields
    /// Id of the network namespace associated with the packet, from the device
    /// or the associated socket (in that order).
    pub(crate) netns: Option<u32>,
    // Dataref fields
    pub(crate) cloned: Option<bool>,
    pub(crate) fclone: Option<bool>,
    pub(crate) users: Option<u8>,
    pub(crate) dataref: Option<u8>,
}

#[derive(Default)]
#[event_section_factory(SkbEvent)]
pub(crate) struct SkbEventFactory {}

impl RawEventSectionFactory for SkbEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut event = SkbEvent::default();

        for section in raw_sections.iter() {
            match section.header.data_type as u64 {
                SECTION_L2 => unmarshal_l2(section, &mut event),
                SECTION_IPV4 => unmarshal_ipv4(section, &mut event),
                SECTION_IPV6 => unmarshal_ipv6(section, &mut event),
                SECTION_TCP => unmarshal_tcp(section, &mut event),
                SECTION_UDP => unmarshal_udp(section, &mut event),
                SECTION_ICMP => unmarshal_icmp(section, &mut event),
                SECTION_DEV => unmarshal_dev(section, &mut event),
                SECTION_NS => unmarshal_ns(section, &mut event),
                SECTION_DATA_REF => unmarshal_data_ref(section, &mut event),
                _ => bail!("Unknown data type"),
            }?;
        }

        Ok(Box::new(event))
    }
}
