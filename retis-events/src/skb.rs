use std::fmt;

use retis_pnet::ethernet::EtherType;

use super::*;
use crate::{event_section, event_type, Formatter};

/// Skb event section.
#[event_section]
#[derive(Default)]
pub struct SkbEvent {
    /// VLAN acceleration tag fields, if any.
    pub vlan_accel: Option<SkbVlanAccelEvent>,
    /// Skb metadata, if any.
    pub meta: Option<SkbMetaEvent>,
    /// Skb data-related and refcnt information, if any.
    pub data_ref: Option<SkbDataRefEvent>,
    /// GSO information.
    pub gso: Option<SkbGsoEvent>,
}

impl EventFmt for SkbEvent {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result {
        let mut space = DelimWriter::new(' ');

        if format.print_ll {
            if let Some(vlan) = &self.vlan_accel {
                space.write(f)?;
                write!(f, "vlan_accel (")?;

                match helpers::etype_str(EtherType::new(vlan.proto)) {
                    Some(etype) => write!(f, "ethertype {etype} ({:#06x})", vlan.proto)?,
                    None => write!(f, "ethertype ({:#06x})", vlan.proto)?,
                }

                write!(
                    f,
                    " vlan {} p {}{})",
                    vlan.vid,
                    vlan.pcp,
                    if vlan.dei { " DEI" } else { "" }
                )?;
            }
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
                    x => write!(f, "unknown ({x}) ")?,
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

    fn can_format(&self, format: &DisplayFormat) -> bool {
        (self.vlan_accel.is_some() && format.print_ll)
            || self.meta.is_some()
            || self.data_ref.is_some()
            || self.gso.is_some()
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

/// VLAN acceleration fields.
#[event_type]
pub struct SkbVlanAccelEvent {
    /// Tag protocol identifier.
    pub proto: u16,
    /// Priority Code Point, also called CoS.
    pub pcp: u8,
    /// Drop eligible indicator.
    pub dei: bool,
    /// VLAN ID.
    pub vid: u16,
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
    ReverseRequest,
    ReverseReply,
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
#[serde(rename_all = "snake_case")]
pub enum SkbIpVersion {
    V4 {
        #[serde(flatten)]
        v4: SkbIpv4Event,
    },
    V6 {
        #[serde(flatten)]
        v6: SkbIpv6Event,
    },
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
