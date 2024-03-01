use std::fmt;

use anyhow::{bail, Result};

use super::bpf::*;
use crate::{
    core::{
        events::{bpf::BpfRawSection, *},
        helpers,
    },
    event_section, event_section_factory, event_type, event_type_no_py,
};

/// Skb event section.
#[event_section]
pub(crate) struct SkbEvent {
    /// Ethernet fields, if any.
    pub(crate) eth: Option<SkbEthEvent>,
    /// ARP fields, if any.
    pub(crate) arp: Option<SkbArpEvent>,
    /// IPv4 or IPv6 fields, if any.
    pub(crate) ip: Option<SkbIpEvent>,
    /// TCP fields, if any.
    pub(crate) tcp: Option<SkbTcpEvent>,
    /// UDP fields, if any.
    pub(crate) udp: Option<SkbUdpEvent>,
    /// ICMP fields, if any.
    pub(crate) icmp: Option<SkbIcmpEvent>,
    /// Net device data, if any.
    pub(crate) dev: Option<SkbDevEvent>,
    /// Net namespace data, if any.
    pub(crate) ns: Option<SkbNsEvent>,
    /// Skb metadata, if any.
    pub(crate) meta: Option<SkbMetaEvent>,
    /// Skb data-related and refcnt information, if any.
    pub(crate) data_ref: Option<SkbDataRefEvent>,
    /// Raw packet and related metadata.
    pub(crate) packet: Option<SkbPacketEvent>,
}

impl EventFmt for SkbEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        let mut len = 0;

        let mut space = DelimWriter::new(' ');

        if let Some(ns) = &self.ns {
            space.write(f)?;
            write!(f, "ns {}", ns.netns)?;
        }

        if let Some(dev) = &self.dev {
            space.write(f)?;

            if dev.ifindex > 0 {
                write!(f, "if {}", dev.ifindex)?;
                if !dev.name.is_empty() {
                    write!(f, " ({})", dev.name)?;
                }
            }
            if let Some(rx_ifindex) = dev.rx_ifindex {
                write!(f, " rxif {}", rx_ifindex)?;
            }
        }

        if let Some(eth) = &self.eth {
            space.write(f)?;

            let ethertype = match helpers::net::etype_str(eth.etype) {
                Some(s) => format!(" {}", s),
                None => String::new(),
            };

            write!(
                f,
                "{} > {} ethertype{} ({:#06x})",
                eth.src, eth.dst, ethertype, eth.etype
            )?;
        }

        if let Some(arp) = &self.arp {
            space.write(f)?;

            match arp.operation {
                ArpOperation::Request => {
                    write!(f, "request who-has {}", arp.tpa)?;
                    if arp.tha != "00:00:00:00:00:00" {
                        write!(f, " ({})", arp.tha)?;
                    }
                    write!(f, " tell {}", arp.spa)?;
                }
                ArpOperation::Reply => {
                    write!(f, "reply {} is-at {}", arp.spa, arp.sha)?;
                }
            }
        }

        if let Some(ip) = &self.ip {
            space.write(f)?;

            // The below is not 100% correct:
            // - IPv4: we use the fixed 20 bytes size as options are rarely used.
            // - IPv6: we do not support extension headers.
            len = match ip.version {
                SkbIpVersion::V4(_) => ip.len - 20,
                _ => ip.len,
            };

            if let Some(tcp) = &self.tcp {
                write!(f, "{}.{} > {}.{}", ip.saddr, tcp.sport, ip.daddr, tcp.dport)?;
            } else if let Some(udp) = &self.udp {
                write!(f, "{}.{} > {}.{}", ip.saddr, udp.sport, ip.daddr, udp.dport)?;
            } else {
                write!(f, "{} > {}", ip.saddr, ip.daddr)?;
            }

            write!(
                f,
                "{}",
                match ip.ecn {
                    1 => " ECT(1)",
                    2 => " ECT(0)",
                    3 => " CE",
                    _ => "",
                }
            )?;

            write!(f, " ttl {}", ip.ttl)?;

            match &ip.version {
                SkbIpVersion::V4(v4) => {
                    write!(f, " tos {:#x} id {} off {}", v4.tos, v4.id, v4.offset * 8)?;

                    let mut flags = Vec::new();
                    // Same order as tcpdump.
                    if v4.flags & 1 << 2 != 0 {
                        flags.push("+");
                    }
                    if v4.flags & 1 << 1 != 0 {
                        flags.push("DF");
                    }
                    if v4.flags & 1 << 0 != 0 {
                        flags.push("rsvd");
                    }

                    if !flags.is_empty() {
                        write!(f, " [{}]", flags.join(","))?;
                    }
                }
                SkbIpVersion::V6(v6) => {
                    if v6.flow_label != 0 {
                        write!(f, " label {:#x}", v6.flow_label)?;
                    }
                }
            }

            let protocol = match helpers::net::protocol_str(ip.protocol) {
                Some(s) => format!(" {}", s),
                None => String::new(),
            };

            write!(f, " len {} proto{} ({})", ip.len, protocol, ip.protocol)?;
        }

        if let Some(tcp) = &self.tcp {
            space.write(f)?;

            let mut flags = Vec::new();
            if tcp.flags & 1 << 0 != 0 {
                flags.push('F');
            }
            if tcp.flags & 1 << 1 != 0 {
                flags.push('S');
            }
            if tcp.flags & 1 << 2 != 0 {
                flags.push('R');
            }
            if tcp.flags & 1 << 3 != 0 {
                flags.push('P');
            }
            if tcp.flags & 1 << 4 != 0 {
                flags.push('.');
            }
            if tcp.flags & 1 << 5 != 0 {
                flags.push('U');
            }
            write!(f, "flags [{}]", flags.into_iter().collect::<String>())?;

            let len = len.saturating_sub(tcp.doff as u16 * 4);
            if len > 0 {
                write!(f, " seq {}:{}", tcp.seq, tcp.seq as u64 + len as u64)?;
            } else {
                write!(f, " seq {}", tcp.seq)?;
            }

            if tcp.flags & 1 << 4 != 0 {
                write!(f, " ack {}", tcp.ack_seq)?;
            }

            write!(f, " win {}", tcp.window)?;
        }

        if let Some(udp) = &self.udp {
            space.write(f)?;
            let len = udp.len;
            // Substract the UDP header size when reporting the length.
            write!(f, "len {}", len.saturating_sub(8))?;
        }

        if let Some(icmp) = &self.icmp {
            space.write(f)?;
            // TODO: text version
            write!(f, "type {} code {}", icmp.r#type, icmp.code)?;
        }

        if self.meta.is_some() || self.data_ref.is_some() {
            space.write(f)?;
            write!(f, "skb [")?;

            if let Some(meta) = &self.meta {
                if meta.csum != 0 {
                    write!(f, "csum {:#x} ", meta.csum)?;
                }
                if meta.hash != 0 {
                    write!(f, "hash {:#x} ", meta.hash)?;
                }
                write!(f, "len {} ", meta.len,)?;
                if meta.data_len != 0 {
                    write!(f, "data_len {} ", meta.data_len)?;
                }
                write!(f, "priority {}", meta.priority)?;
            }

            if self.meta.is_some() && self.data_ref.is_some() {
                write!(f, " ")?;
            }

            if let Some(dataref) = &self.data_ref {
                if dataref.nohdr {
                    write!(f, "nohdr ")?;
                }
                if dataref.cloned {
                    write!(f, "cloned ")?;
                }
                if dataref.fclone > 0 {
                    write!(f, "fclone {} ", dataref.fclone)?;
                }
                write!(f, "users {} dataref {}", dataref.users, dataref.dataref)?;
            }

            write!(f, "]")?;
        }

        Ok(())
    }
}

/// Ethernet fields.
#[event_type]
pub(crate) struct SkbEthEvent {
    /// Ethertype.
    pub(crate) etype: u16,
    /// Source MAC address.
    pub(crate) src: String,
    /// Destination MAC address.
    pub(crate) dst: String,
}

/// ARP fields.
#[event_type]
pub(crate) struct SkbArpEvent {
    /// Operation type.
    pub(crate) operation: ArpOperation,
    /// Sender hardware address.
    pub(crate) sha: String,
    /// Sender protocol address.
    pub(crate) spa: String,
    /// Target hardware address.
    pub(crate) tha: String,
    /// Target protocol address.
    pub(crate) tpa: String,
}

/// ARP operation type.
#[event_type]
pub(crate) enum ArpOperation {
    Request,
    Reply,
}

/// IPv4/IPv6 fields.
#[event_type]
pub(crate) struct SkbIpEvent {
    /// Source IP address.
    pub(crate) saddr: String,
    /// Destination IP address.
    pub(crate) daddr: String,
    /// IP version: 4 or 6.
    #[serde(flatten)]
    pub(crate) version: SkbIpVersion,
    /// L4 protocol, from IPv4 "protocol" field or IPv6 "next header" one.
    pub(crate) protocol: u8,
    /// "total len" from the IPv4 header or "payload length" from the IPv6 one.
    pub(crate) len: u16,
    /// TTL in the IPv4 header and hop limit in the IPv6 one.
    pub(crate) ttl: u8,
    /// ECN.
    pub(crate) ecn: u8,
}

/// IP version and specific fields.
#[event_type_no_py]
pub(crate) enum SkbIpVersion {
    #[serde(rename = "v4")]
    V4(SkbIpv4Event),
    #[serde(rename = "v6")]
    V6(SkbIpv6Event),
}

/// IPv4 specific fields.
#[event_type]
pub struct SkbIpv4Event {
    /// Type of service.
    pub(crate) tos: u8,
    /// Identification.
    pub(crate) id: u16,
    /// Flags (CE, DF, MF).
    pub(crate) flags: u8,
    /// Fragment offset.
    pub(crate) offset: u16,
}

/// IPv6 specific fields.
#[event_type]
pub struct SkbIpv6Event {
    /// Flow label.
    pub(crate) flow_label: u32,
}

/// TCP fields.
#[event_type]
pub(crate) struct SkbTcpEvent {
    /// Source port.
    pub(crate) sport: u16,
    /// Destination port.
    pub(crate) dport: u16,
    pub(crate) seq: u32,
    pub(crate) ack_seq: u32,
    pub(crate) window: u16,
    /// Data offset.
    pub(crate) doff: u8,
    /// Bitfield of TCP flags as defined in `struct tcphdr` in the kernel.
    pub(crate) flags: u8,
}

/// UDP fields.
#[event_type]
pub(crate) struct SkbUdpEvent {
    /// Source port.
    pub(crate) sport: u16,
    /// Destination port.
    pub(crate) dport: u16,
    /// Length from the UDP header.
    pub(crate) len: u16,
}

/// ICMP fields.
#[event_type]
pub(crate) struct SkbIcmpEvent {
    pub(crate) r#type: u8,
    pub(crate) code: u8,
}

/// Network device fields.
#[event_type]
#[derive(Default)]
pub(crate) struct SkbDevEvent {
    /// Net device name associated with the packet, from `skb->dev->name`.
    pub(crate) name: String,
    /// Net device ifindex associated with the packet, from `skb->dev->ifindex`.
    pub(crate) ifindex: u32,
    /// Index if the net device the packet arrived on, from `skb->skb_iif`.
    pub(crate) rx_ifindex: Option<u32>,
}

/// Network namespace fields.
#[event_type]
pub(crate) struct SkbNsEvent {
    /// Id of the network namespace associated with the packet, from the device
    /// or the associated socket (in that order).
    pub(crate) netns: u32,
}

/// Skb metadata & releated fields.
#[event_type]
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
#[event_type]
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

/// Raw packet and related metadata extracted from skbs.
#[event_type]
pub(crate) struct SkbPacketEvent {
    /// Length of the packet.
    pub(crate) len: u32,
    /// Lenght of the capture. <= len.
    pub(crate) capture_len: u32,
    /// Raw packet data.
    pub(crate) packet: Vec<u8>,
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
                SECTION_ARP => event.arp = Some(unmarshal_arp(section)?),
                SECTION_IPV4 => event.ip = Some(unmarshal_ipv4(section)?),
                SECTION_IPV6 => event.ip = Some(unmarshal_ipv6(section)?),
                SECTION_TCP => event.tcp = Some(unmarshal_tcp(section)?),
                SECTION_UDP => event.udp = Some(unmarshal_udp(section)?),
                SECTION_ICMP => event.icmp = Some(unmarshal_icmp(section)?),
                SECTION_DEV => event.dev = unmarshal_dev(section)?,
                SECTION_NS => event.ns = Some(unmarshal_ns(section)?),
                SECTION_META => event.meta = Some(unmarshal_meta(section)?),
                SECTION_DATA_REF => event.data_ref = Some(unmarshal_data_ref(section)?),
                SECTION_PACKET => event.packet = Some(unmarshal_packet(section)?),
                _ => bail!("Unknown data type"),
            }
        }

        Ok(Box::new(event))
    }
}
