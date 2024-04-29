use std::fmt;

use super::*;
use crate::{event_section, event_type};

#[event_type]
#[derive(Default)]
pub(crate) enum ZoneDir {
    Original,
    Reply,
    Default,
    #[default]
    None,
}

#[event_type]
#[derive(Default)]
pub(crate) struct CtTcp {
    /// TCP source port
    pub(crate) sport: u16,
    /// TCP destination port
    pub(crate) dport: u16,
}

#[event_type]
#[derive(Default)]
pub(crate) struct CtUdp {
    /// UDP source port
    pub(crate) sport: u16,
    /// UDP destination port
    pub(crate) dport: u16,
}

#[event_type]
#[derive(Default)]
pub(crate) struct CtIcmp {
    /// ICMP code
    pub(crate) code: u8,
    /// ICMP type
    pub(crate) r#type: u8,
    /// ICMP ID
    pub(crate) id: u16,
}

#[event_type]
#[serde(rename_all = "snake_case")]
pub(crate) enum CtProto {
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
pub(crate) enum CtIpVersion {
    #[default]
    V4,
    V6,
}

#[event_type]
#[derive(Default)]
pub(crate) struct CtIp {
    /// Source IP address
    pub(crate) src: String,
    /// Destination IP address
    pub(crate) dst: String,
    /// IP version
    pub(crate) version: CtIpVersion,
}

/// Conntrack tuple.
#[event_type]
#[derive(Default)]
pub(crate) struct CtTuple {
    /// IP address
    pub(crate) ip: CtIp,
    /// Protocol information
    pub(crate) proto: CtProto,
}

/// Conntrack state
#[event_type]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub(crate) enum CtState {
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
pub(crate) struct CtEvent {
    /// Zone ID
    pub(crate) zone_id: u16,
    /// Zone direction
    pub(crate) zone_dir: ZoneDir,
    /// Original tuple
    pub(crate) orig: CtTuple,
    /// Reply tuple
    pub(crate) reply: CtTuple,
    /// Packet's conntrack state
    pub(crate) state: CtState,
    /// TCP state; if any
    pub(crate) tcp_state: Option<String>,
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
