use std::fmt;

use anyhow::Result;

use super::bpf::*;
use crate::{
    core::events::{bpf::BpfRawSection, *},
    event_section, event_section_factory,
};

#[derive(Default, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) enum ZoneDir {
    Original,
    Reply,
    Default,
    #[default]
    None,
}

#[derive(Default, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct CtTcp {
    /// TCP source port
    pub(crate) sport: u16,
    /// TCP destination port
    pub(crate) dport: u16,
}

#[derive(Default, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct CtUdp {
    /// UDP source port
    pub(crate) sport: u16,
    /// UDP destination port
    pub(crate) dport: u16,
}

#[derive(Default, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct CtIcmp {
    /// ICMP code
    pub(crate) code: u8,
    /// ICMP type
    pub(crate) r#type: u8,
    /// ICMP ID
    pub(crate) id: u16,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
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

#[derive(Default, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CtIpVersion {
    #[default]
    V4,
    V6,
}

#[derive(Default, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct CtIp {
    /// Source IP address
    pub(crate) src: String,
    /// Destination IP address
    pub(crate) dst: String,
    /// IP version
    pub(crate) version: CtIpVersion,
}

/// Conntrack tuple.
#[derive(Default, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct CtTuple {
    /// IP address
    pub(crate) ip: CtIp,
    /// Protocol information
    pub(crate) proto: CtProto,
}
/// Conntrack event
#[event_section]
pub(crate) struct CtEvent {
    /// Zone ID
    pub(crate) zone_id: u16,
    /// Zone direction
    pub(crate) zone_dir: ZoneDir,
    /// Original tuple
    pub(crate) orig: CtTuple,
    /// Reply tuple
    pub(crate) reply: CtTuple,
}
impl EventFmt for CtEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        match (&self.orig.proto, &self.reply.proto) {
            (CtProto::Tcp(tcp_orig), CtProto::Tcp(tcp_reply)) => {
                write!(
                    f,
                    "tcp orig [{}.{} > {}.{}] reply [{}.{} > {}.{}] ",
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

#[derive(Default)]
#[event_section_factory(CtEvent)]
pub(crate) struct CtEventFactory {}

impl RawEventSectionFactory for CtEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        Ok(Box::new(unmarshal_ct(raw_sections)?))
    }
}
