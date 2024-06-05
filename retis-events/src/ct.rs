use std::fmt;

use super::*;
use crate::{event_section, event_type};

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
    Tcp(CtTcp),
    Udp(CtUdp),
    Icmp(CtIcmp),
}
impl Default for CtProto {
    fn default() -> Self {
        CtProto::Tcp(CtTcp::default())
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
#[event_section("ct")]
pub struct CtEvent {
    /// Zone ID
    pub zone_id: u16,
    /// Zone direction
    pub zone_dir: ZoneDir,
    /// Original tuple
    pub orig: CtTuple,
    /// Reply tuple
    pub reply: CtTuple,
    /// Packet's conntrack state
    pub state: CtState,
    /// TCP state; if any
    pub tcp_state: Option<String>,
}

impl EventFmt for CtEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        use CtState::*;
        match self.state {
            Established => write!(f, "ct_state ESTABLISHED ")?,
            Related => write!(f, "ct_state RELATED ")?,
            New => write!(f, "ct_state NEW ")?,
            Reply => write!(f, "ct_state REPLY ")?,
            RelatedReply => write!(f, "ct_state RELATED_REPLY ")?,
            Untracked => write!(f, "ct_state UNTRACKED ")?,
        }

        match (&self.orig.proto, &self.reply.proto) {
            (CtProto::Tcp(tcp_orig), CtProto::Tcp(tcp_reply)) => {
                write!(
                    f,
                    "tcp ({}) orig [{}.{} > {}.{}] reply [{}.{} > {}.{}] ",
                    self.tcp_state.as_ref().unwrap_or(&"UNKNOWN".to_string()),
                    self.orig.ip.src,
                    tcp_orig.sport,
                    self.orig.ip.dst,
                    tcp_orig.dport,
                    self.reply.ip.src,
                    tcp_reply.sport,
                    self.reply.ip.dst,
                    tcp_reply.dport,
                )?;
            }
            (CtProto::Udp(udp_orig), CtProto::Udp(udp_reply)) => {
                write!(
                    f,
                    "udp orig [{}.{} > {}.{}] reply [{}.{} > {}.{}] ",
                    self.orig.ip.src,
                    udp_orig.sport,
                    self.orig.ip.dst,
                    udp_orig.dport,
                    self.reply.ip.src,
                    udp_reply.sport,
                    self.reply.ip.dst,
                    udp_reply.dport,
                )?;
            }
            (CtProto::Icmp(icmp_orig), CtProto::Icmp(icmp_reply)) => {
                write!(f, "icmp orig [{} > {} type {} code {} id {}] reply [{} > {} type {} code {} id {}] ",
                           self.orig.ip.src,
                           self.orig.ip.dst,
                           icmp_orig.r#type,
                           icmp_orig.code,
                           icmp_orig.id,
                           self.reply.ip.src,
                           self.reply.ip.dst,
                           icmp_reply.r#type,
                           icmp_reply.code,
                           icmp_reply.id,
                           )?;
            }
            _ => (),
        }
        match self.zone_dir {
            ZoneDir::Original => write!(f, "orig-zone {}", self.zone_id)?,
            ZoneDir::Reply => write!(f, "reply-zone {}", self.zone_id)?,
            ZoneDir::Default => write!(f, "zone {}", self.zone_id)?,
            ZoneDir::None => (),
        }

        Ok(())
    }
}
