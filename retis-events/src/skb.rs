use std::{
    cell::RefCell,
    fmt,
    io::{self, Read, Write},
    process::*,
    str,
    sync::Mutex,
};

use anyhow::{anyhow, bail, Result};
use log::{debug, error};
use once_cell::sync::OnceCell;

use super::{helpers::RawPacket, *};
use crate::{event_section, event_type, Formatter};

static TCPDUMP: OnceCell<Tcpdump> = OnceCell::new();

fn tcpdump(format: &DisplayFormat) -> Result<&'static Tcpdump> {
    TCPDUMP.get_or_try_init(|| Tcpdump::new(format))
}

struct Tcpdump {
    command: Mutex<RefCell<InnerCommand>>,
}

struct InnerCommand {
    cmd: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Tcpdump {
    fn new(format: &DisplayFormat) -> Result<Self> {
        let mut cmd = Command::new("tcpdump");
        cmd.args([
            "-l",
            "--absolute-tcp-sequence-number",
            "--dont-verify-checksums",
            "-nn",
            "-t",
            "-r",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

        if format.print_ll {
            cmd.arg("-e");
        }

        let mut cmd = match cmd.spawn() {
            Ok(cmd) => cmd,
            Err(e) => bail!("Cannot execute tcpdump: {e}"),
        };

        let mut stdin = cmd
            .stdin
            .take()
            .ok_or_else(|| anyhow!("Could not take stdin"))?;
        let stdout = cmd
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Could not take stdout"))?;

        // Write pcap file header.
        #[rustfmt::skip]
        stdin.write_all(&[
            0xd4, 0xc3, 0xb2, 0xa1,
            0x02, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x04, 0x00,
            0x01, 0x00, 0x00, 0x00,
        ])?;

        Ok(Self {
            command: Mutex::new(RefCell::new(InnerCommand { cmd, stdin, stdout })),
        })
    }

    fn display_event(&self, f: &mut Formatter, event: &SkbPacketEvent) -> Result<()> {
        let mut buf = Vec::new();
        buf.write_all(&0_u32.to_ne_bytes())?;
        buf.write_all(&0_u32.to_ne_bytes())?;
        buf.write_all(&event.capture_len.to_ne_bytes())?;
        buf.write_all(&event.len.to_ne_bytes())?;
        buf.write_all(&event.packet.0)?;

        let cmd = self.command.lock().unwrap();
        let mut cmd = cmd.borrow_mut();

        cmd.stdin.write_all(&buf)?;

        // We're making a blocking read below. This should be fine:
        // - tcpdump is configured to write the packet output at once.
        // - tcpdump will issue an output whatever the packet data and capture
        //   length given above; as long as the pcap header is transmitted and
        //   valid.
        loop {
            let mut buf = [0; 250];
            let read = cmd.stdout.read(&mut buf).unwrap();

            if read < 250 {
                // Skip the newline at EOL.
                write!(f, "{}", str::from_utf8(&buf[..read - 1])?)?;
                break;
            }
            write!(f, "{}", str::from_utf8(&buf[..read])?)?;
        }

        Ok(())
    }
}

/// Skb event section.
#[event_section(SectionId::Skb)]
#[derive(Default)]
pub struct SkbEvent {
    /// VLAN acceleration tag fields, if any.
    pub vlan_accel: Option<SkbVlanAccelEvent>,
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

    // Sections below are kept for backward compatibility but aren't used
    // anymore. Use the `SkbPacketEvent` event section instead.
    pub eth: Option<SkbEthEvent>,
    pub arp: Option<SkbArpEvent>,
    pub ip: Option<SkbIpEvent>,
    pub tcp: Option<SkbTcpEvent>,
    pub udp: Option<SkbUdpEvent>,
    pub icmp: Option<SkbIcmpEvent>,
    pub icmpv6: Option<SkbIcmpV6Event>,
}

impl EventFmt for SkbEvent {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result {
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

        // Only print VLAN accel information if we print the LL one, as
        // otherwise we would print this one but not the VLAN data in the
        // payload. This would be quite confusing.
        if format.print_ll {
            if let Some(vlan) = &self.vlan_accel {
                space.write(f)?;

                write!(
                    f,
                    "vlan_accel (id {} prio {}{})",
                    vlan.vid,
                    vlan.pcp,
                    if vlan.dei { " drop" } else { "" }
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

        // Do not add any other section than the raw packet one after this.
        if format.multiline && space.used() {
            writeln!(f)?;
            space.reset();
        }

        if let Some(packet) = &self.packet {
            space.write(f)?;

            match tcpdump(format) {
                Ok(tcpdump) => {
                    if let Err(e) = tcpdump.display_event(f, packet) {
                        // BrokenPipe error will be seen on Ctrl+C, silence it.
                        // We're not using `Running` here as it is outside
                        // retis-events.
                        if e.downcast_ref::<io::Error>()
                            .map(|e| e.kind() == io::ErrorKind::BrokenPipe)
                            != Some(true)
                        {
                            write!(f, "unknown packet")?;
                            error!("Cannot format packet: {e}");
                        } else {
                            debug!("Got broken pipe from tcpdump thread");
                        }
                    }
                }
                Err(e) => {
                    write!(f, "unknown packet")?;
                    error!("{e}");
                }
            }
        } else {
            space.write(f)?;
            write!(f, "unknown packet")?;
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

/// VLAN acceleration fields.
#[event_type]
pub struct SkbVlanAccelEvent {
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
