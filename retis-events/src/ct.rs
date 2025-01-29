use std::fmt;

use super::{helpers::U128, *};
use crate::{event_section, event_type, Formatter};

#[event_type]
#[derive(Default)]
pub enum ZoneDir {
    Original,
    Reply,
    Default,
    #[default]
    None,
}

#[event_type]
#[derive(Default)]
pub struct CtTcp {
    /// TCP source port
    pub sport: u16,
    /// TCP destination port
    pub dport: u16,
}

#[event_type]
#[derive(Default)]
pub struct CtUdp {
    /// UDP source port
    pub sport: u16,
    /// UDP destination port
    pub dport: u16,
}

#[event_type]
#[derive(Default)]
pub struct CtIcmp {
    /// ICMP code
    pub code: u8,
    /// ICMP type
    pub r#type: u8,
    /// ICMP ID
    pub id: u16,
}

#[event_type]
#[serde(rename_all = "snake_case")]
pub enum CtProto {
    Tcp {
        #[serde(flatten)]
        tcp: CtTcp,
    },
    Udp {
        #[serde(flatten)]
        udp: CtUdp,
    },
    Icmp {
        #[serde(flatten)]
        icmp: CtIcmp,
    },
}
impl Default for CtProto {
    fn default() -> Self {
        CtProto::Tcp {
            tcp: CtTcp::default(),
        }
    }
}

#[event_type]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum CtIpVersion {
    #[default]
    V4,
    V6,
}

#[event_type]
#[derive(Default)]
pub struct CtIp {
    /// Source IP address
    pub src: String,
    /// Destination IP address
    pub dst: String,
    /// IP version
    pub version: CtIpVersion,
}

/// Conntrack tuple.
#[event_type]
#[derive(Default)]
pub struct CtTuple {
    /// IP address
    pub ip: CtIp,
    /// Protocol information
    pub proto: CtProto,
}

/// Conntrack state
#[event_type]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum CtState {
    Established,
    Related,
    New,
    // Represents both IP_CT_REPLY and IP_CT_ESTABLISHED_REPLY as they have the same value.
    Reply,
    RelatedReply,
    #[default]
    Untracked,
}
/// Conntrack event
#[event_section]
pub struct CtEvent {
    /// Packet's conntrack state
    pub state: CtState,
    /// Base connection event.
    #[serde(flatten)]
    pub base: CtConnEvent,
    /// Parent connection information.
    pub parent: Option<CtConnEvent>,
}

/// Conntrack connection information
#[event_type]
#[derive(Default)]
pub struct CtConnEvent {
    /// Zone ID
    pub zone_id: u16,
    /// Zone direction
    pub zone_dir: ZoneDir,
    /// Original tuple
    pub orig: CtTuple,
    /// Reply tuple
    pub reply: CtTuple,
    /// TCP state; if any
    pub tcp_state: Option<String>,
    /// Connection mark tracking label
    pub mark: Option<u32>,
    /// Connection tracking labels.
    pub labels: Option<U128>,
    /// nf_conn status (ct->status).
    pub ct_status: u64,
}

impl EventFmt for CtEvent {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result {
        use CtState::*;
        match self.state {
            Established => write!(f, "ct_state ESTABLISHED ")?,
            Related => write!(f, "ct_state RELATED ")?,
            New => write!(f, "ct_state NEW ")?,
            Reply => write!(f, "ct_state REPLY ")?,
            RelatedReply => write!(f, "ct_state RELATED_REPLY ")?,
            Untracked => write!(f, "ct_state UNTRACKED ")?,
        }

        Self::format_conn(&self.base, f)?;

        if let Some(parent) = &self.parent {
            if format.multiline {
                write!(f, "\n\\")?;
            }

            write!(f, " parent [")?;
            Self::format_conn(parent, f)?;
            write!(f, "]")?;
        }

        Ok(())
    }
}

impl CtEvent {
    fn format_conn(conn: &CtConnEvent, f: &mut Formatter) -> fmt::Result {
        write!(f, "status {:#x} ", conn.ct_status)?;

        match (&conn.orig.proto, &conn.reply.proto) {
            (CtProto::Tcp { tcp: tcp_orig }, CtProto::Tcp { tcp: tcp_reply }) => {
                write!(
                    f,
                    "tcp ({}) orig [{}.{} > {}.{}] reply [{}.{} > {}.{}] ",
                    conn.tcp_state.as_ref().unwrap_or(&"UNKNOWN".to_string()),
                    conn.orig.ip.src,
                    tcp_orig.sport,
                    conn.orig.ip.dst,
                    tcp_orig.dport,
                    conn.reply.ip.src,
                    tcp_reply.sport,
                    conn.reply.ip.dst,
                    tcp_reply.dport,
                )?;
            }
            (CtProto::Udp { udp: udp_orig }, CtProto::Udp { udp: udp_reply }) => {
                write!(
                    f,
                    "udp orig [{}.{} > {}.{}] reply [{}.{} > {}.{}] ",
                    conn.orig.ip.src,
                    udp_orig.sport,
                    conn.orig.ip.dst,
                    udp_orig.dport,
                    conn.reply.ip.src,
                    udp_reply.sport,
                    conn.reply.ip.dst,
                    udp_reply.dport,
                )?;
            }
            (CtProto::Icmp { icmp: icmp_orig }, CtProto::Icmp { icmp: icmp_reply }) => {
                write!(f, "icmp orig [{} > {} type {} code {} id {}] reply [{} > {} type {} code {} id {}] ",
                           conn.orig.ip.src,
                           conn.orig.ip.dst,
                           icmp_orig.r#type,
                           icmp_orig.code,
                           icmp_orig.id,
                           conn.reply.ip.src,
                           conn.reply.ip.dst,
                           icmp_reply.r#type,
                           icmp_reply.code,
                           icmp_reply.id,
                           )?;
            }
            _ => (),
        }
        match conn.zone_dir {
            ZoneDir::Original => write!(f, "orig-zone {}", conn.zone_id)?,
            ZoneDir::Reply => write!(f, "reply-zone {}", conn.zone_id)?,
            ZoneDir::Default => write!(f, "zone {}", conn.zone_id)?,
            ZoneDir::None => (),
        }

        if let Some(mark) = conn.mark {
            write!(f, " mark {mark}")?;
        }

        if let Some(labels) = &conn.labels {
            write!(f, " labels {:#x}", labels.bits())?;
        }

        Ok(())
    }
}
