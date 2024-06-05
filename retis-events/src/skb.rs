use std::fmt;

use super::{
    net::{etype_str, protocol_str, RawPacket},
    *,
};
use crate::{event_section, event_type};

/// Skb event section.
#[event_section("skb")]
pub struct SkbEvent {
    /// Ethernet fields, if any.
    pub eth: Option<SkbEthEvent>,
    /// ARP fields, if any.
    pub arp: Option<SkbArpEvent>,
    /// IPv4 or IPv6 fields, if any.
    pub ip: Option<SkbIpEvent>,
    /// TCP fields, if any.
    pub tcp: Option<SkbTcpEvent>,
    /// UDP fields, if any.
    pub udp: Option<SkbUdpEvent>,
    /// ICMP fields, if any.
    pub icmp: Option<SkbIcmpEvent>,
    /// ICMPv6 fields, if any.
    pub icmpv6: Option<SkbIcmpV6Event>,
    /// Net device data, if any.
    pub dev: Option<SkbDevEvent>,
    /// Net namespace data, if any.
    pub ns: Option<SkbNsEvent>,
    /// Skb metadata, if any.
    pub meta: Option<SkbMetaEvent>,
    /// Skb data-related and refcnt information, if any.
    pub data_ref: Option<SkbDataRefEvent>,
    /// GSO information.
    pub gso: Option<SkbGsoEvent>,
    /// Raw packet and related metadata.
    pub packet: Option<SkbPacketEvent>,
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

            let ethertype = match etype_str(eth.etype) {
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
                SkbIpVersion::V4(_) => ip.len.saturating_sub(20),
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

            let protocol = match protocol_str(ip.protocol) {
                Some(s) => format!(" {}", s),
                None => String::new(),
            };

            // In some rare cases the IP header might not be fully filled yet,
            // length might be unset.
            if ip.len != 0 {
                write!(f, " len {}", ip.len)?;
            }

            write!(f, " proto{} ({})", protocol, ip.protocol)?;
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

        if let Some(icmpv6) = &self.icmpv6 {
            space.write(f)?;
            // TODO: text version
            write!(f, "type {} code {}", icmpv6.r#type, icmpv6.code)?;
        }

        if self.meta.is_some() || self.data_ref.is_some() {
            space.write(f)?;
            write!(f, "skb [")?;

            if let Some(meta) = &self.meta {
                write!(f, "csum ")?;
                match meta.ip_summed {
                    0 => write!(f, "none ")?,
                    1 => write!(f, "unnecessary (level {}) ", meta.csum_level)?,
                    2 => write!(f, "complete ({:#x}) ", meta.csum)?,
                    3 => {
                        let start = meta.csum & 0xffff;
                        let off = meta.csum >> 16;
                        write!(f, "partial (start {start} off {off}) ")?;
                    }
                    x => write!(f, "unknown ({}) ", x)?,
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

        if let Some(gso) = &self.gso {
            space.write(f)?;
            write!(f, "gso [type {:#x} ", gso.r#type)?;

            if gso.flags != 0 {
                write!(f, "flags {:#x} ", gso.flags)?;
            }

            if gso.frags != 0 {
                write!(f, "frags {} ", gso.frags)?;
            }

            if gso.segs != 0 {
                write!(f, "segs {} ", gso.segs)?;
            }

            write!(f, "size {}]", gso.size)?;
        }

        Ok(())
    }
}

/// Ethernet fields.
#[event_type]
pub struct SkbEthEvent {
    /// Ethertype.
    pub etype: u16,
    /// Source MAC address.
    pub src: String,
    /// Destination MAC address.
    pub dst: String,
}

/// ARP fields.
#[event_type]
pub struct SkbArpEvent {
    /// Operation type.
    pub operation: ArpOperation,
    /// Sender hardware address.
    pub sha: String,
    /// Sender protocol address.
    pub spa: String,
    /// Target hardware address.
    pub tha: String,
    /// Target protocol address.
    pub tpa: String,
}

/// ARP operation type.
#[event_type]
pub enum ArpOperation {
    Request,
    Reply,
}

/// IPv4/IPv6 fields.
#[event_type]
pub struct SkbIpEvent {
    /// Source IP address.
    pub saddr: String,
    /// Destination IP address.
    pub daddr: String,
    /// IP version: 4 or 6.
    #[serde(flatten)]
    pub version: SkbIpVersion,
    /// L4 protocol, from IPv4 "protocol" field or IPv6 "next header" one.
    pub protocol: u8,
    /// "total len" from the IPv4 header or "payload length" from the IPv6 one.
    pub len: u16,
    /// TTL in the IPv4 header and hop limit in the IPv6 one.
    pub ttl: u8,
    /// ECN.
    pub ecn: u8,
}

/// IP version and specific fields.
#[event_type]
pub enum SkbIpVersion {
    #[serde(rename = "v4")]
    V4(SkbIpv4Event),
    #[serde(rename = "v6")]
    V6(SkbIpv6Event),
}

/// IPv4 specific fields.
#[event_type]
pub struct SkbIpv4Event {
    /// Type of service.
    pub tos: u8,
    /// Identification.
    pub id: u16,
    /// Flags (CE, DF, MF).
    pub flags: u8,
    /// Fragment offset.
    pub offset: u16,
}

/// IPv6 specific fields.
#[event_type]
pub struct SkbIpv6Event {
    /// Flow label.
    pub flow_label: u32,
}

/// TCP fields.
#[event_type]
pub struct SkbTcpEvent {
    /// Source port.
    pub sport: u16,
    /// Destination port.
    pub dport: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub window: u16,
    /// Data offset.
    pub doff: u8,
    /// Bitfield of TCP flags as defined in `struct tcphdr` in the kernel.
    pub flags: u8,
}

/// UDP fields.
#[event_type]
pub struct SkbUdpEvent {
    /// Source port.
    pub sport: u16,
    /// Destination port.
    pub dport: u16,
    /// Length from the UDP header.
    pub len: u16,
}

/// ICMP fields.
#[event_type]
pub struct SkbIcmpEvent {
    pub r#type: u8,
    pub code: u8,
}

/// ICMPv6 fields.
#[event_type]
pub struct SkbIcmpV6Event {
    pub r#type: u8,
    pub code: u8,
}

/// Network device fields.
#[event_type]
#[derive(Default)]
pub struct SkbDevEvent {
    /// Net device name associated with the packet, from `skb->dev->name`.
    pub name: String,
    /// Net device ifindex associated with the packet, from `skb->dev->ifindex`.
    pub ifindex: u32,
    /// Index if the net device the packet arrived on, from `skb->skb_iif`.
    pub rx_ifindex: Option<u32>,
}

/// Network namespace fields.
#[event_type]
pub struct SkbNsEvent {
    /// Id of the network namespace associated with the packet, from the device
    /// or the associated socket (in that order).
    pub netns: u32,
}

/// Skb metadata & releated fields.
#[event_type]
pub struct SkbMetaEvent {
    /// Total number of bytes in the packet.
    pub len: u32,
    /// Total number of bytes in the page buffer area.
    pub data_len: u32,
    /// Packet hash (!= hash of the packet data).
    pub hash: u32,
    /// Checksum status.
    pub ip_summed: u8,
    /// Packet checksum (ip_summed == CHECKSUM_COMPLETE) or checksum
    /// (start << 16)|offset (ip_summed == CHECKSUM_PARTIAL).
    pub csum: u32,
    /// Checksum level (ip_summed == CHECKSUM_PARTIAL)
    pub csum_level: u8,
    /// QoS priority.
    pub priority: u32,
}

/// Skb data & refcnt fields.
#[event_type]
pub struct SkbDataRefEvent {
    /// Payload reference only.
    pub nohdr: bool,
    /// Is the skb a clone?
    pub cloned: bool,
    /// Skb fast clone information.
    pub fclone: u8,
    /// Users count.
    pub users: u8,
    /// Data refcount.
    pub dataref: u8,
}

/// GSO information.
#[event_type]
pub struct SkbGsoEvent {
    /// GSO flags, see `SKBFL_*` in include/linux/skbuff.h
    pub flags: u8,
    /// Number of fragments in `skb_shared_info->frags`.
    pub frags: u8,
    /// GSO size.
    pub size: u32,
    /// Number of GSO segments.
    pub segs: u32,
    /// GSO type, see `SKB_GSO_*` in include/linux/skbuff.h
    pub r#type: u32,
}

/// Raw packet and related metadata extracted from skbs.
#[event_type]
pub struct SkbPacketEvent {
    /// Length of the packet.
    pub len: u32,
    /// Lenght of the capture. <= len.
    pub capture_len: u32,
    /// Raw packet data.
    pub packet: RawPacket,
}
