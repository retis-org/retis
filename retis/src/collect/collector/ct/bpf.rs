//! Rust<>BPF types definitions for the ct module.
//! Please keep this file in sync with its BPF counterpart in bpf/ct.bpf.c
use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use btf_rs::Type;
use std::net::Ipv6Addr;

use crate::{
    bindings::ct_uapi::*,
    core::{
        events::{
            parse_raw_section, BpfRawSection, EventSectionFactory, FactoryId,
            RawEventSectionFactory,
        },
        inspect::inspector,
    },
    event_section_factory,
    events::{helpers::U128, *},
    helpers,
};

#[event_section_factory(FactoryId::Ct)]
#[derive(Default)]
pub(crate) struct CtEventFactory {
    mark_available: bool,
    labels_available: bool,
    tcp_states: HashMap<i32, String>,
}

impl RawEventSectionFactory for CtEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut event = CtEvent {
            state: {
                let raw = parse_raw_section::<ct_meta_event>(
                    raw_sections
                        .iter()
                        .find(|s| s.header.data_type as u32 == SECTION_META)
                        .ok_or_else(|| anyhow!("CT BPF event does not have a meta section"))?,
                )?;

                use CtState::*;
                // These values must be kept in sync with the ones defined in:
                // include/uapi/linux/netfilter/nf_conntrack_common.h
                match raw.state {
                    0 => Established,
                    1 => Related,
                    2 => New,
                    3 => Reply,
                    4 => RelatedReply,
                    7 => Untracked,
                    _ => bail!("ct: unsupported ct state {}", raw.state),
                }
            },
            base: self.unmarshal_ct(
                raw_sections
                    .iter()
                    .find(|s| s.header.data_type as u32 == SECTION_BASE_CONN)
                    .ok_or_else(|| anyhow!("CT BPF event does not have a base section"))?,
            )?,
            parent: None,
        };

        if let Some(raw_section) = raw_sections
            .iter()
            .find(|s| s.header.data_type as u32 == SECTION_PARENT_CONN)
        {
            event.parent = Some(self.unmarshal_ct(raw_section)?);
        }

        Ok(Box::new(event))
    }
}

impl CtEventFactory {
    pub(crate) fn new() -> Result<Self> {
        let inspector = inspector()?;

        let mut me = Self {
            mark_available: matches!(
                inspector
                    .kernel
                    .get_config_option("CONFIG_NF_CONNTRACK_MARK"),
                Ok(Some("y")) | Err(_)
            ),
            labels_available: matches!(
                inspector
                    .kernel
                    .get_config_option("CONFIG_NF_CONNTRACK_LABELS"),
                Ok(Some("y")) | Err(_)
            ),
            ..Default::default()
        };

        me.parse_tcp_states()?;
        Ok(me)
    }

    fn parse_tcp_states(&mut self) -> Result<()> {
        if let Ok(types) = inspector()?
            .kernel
            .btf
            .resolve_types_by_name("tcp_conntrack")
        {
            if let Some((btf, Type::Enum(r#enum))) =
                types.iter().find(|(_, t)| matches!(t, Type::Enum(_)))
            {
                for member in r#enum.members.iter() {
                    if (member.val() as i32) < 0 {
                        continue;
                    }
                    self.tcp_states.insert(
                        member.val() as i32,
                        btf.resolve_name(member)?
                            .trim_start_matches("TCP_CONNTRACK_")
                            .to_string(),
                    );
                }
            }
        }

        Ok(())
    }

    pub(super) fn unmarshal_ct(&mut self, raw_section: &BpfRawSection) -> Result<CtConnEvent> {
        let raw = parse_raw_section::<ct_event>(raw_section)?;
        let flags = raw.flags;

        let zone_dir = match flags {
            x if (x & (RETIS_CT_DIR_ORIG | RETIS_CT_DIR_REPLY)
                == (RETIS_CT_DIR_ORIG | RETIS_CT_DIR_REPLY)) =>
            {
                ZoneDir::Default
            }
            x if (x & RETIS_CT_DIR_ORIG != 0) => ZoneDir::Original,
            x if (x & RETIS_CT_DIR_REPLY != 0) => ZoneDir::Reply,
            _ => ZoneDir::None,
        };

        let (orig_ip, reply_ip) = if flags & RETIS_CT_IPV4 != 0 {
            let s = unsafe { raw.orig.src.addr.ipv4 };
            let d = unsafe { raw.orig.dst.addr.ipv4 };
            let orig = CtIp {
                src: helpers::net::parse_ipv4_addr(u32::from_be(s))?,
                dst: helpers::net::parse_ipv4_addr(u32::from_be(d))?,
                version: CtIpVersion::V4,
            };
            let s = unsafe { raw.reply.src.addr.ipv4 };
            let d = unsafe { raw.reply.dst.addr.ipv4 };
            let reply = CtIp {
                src: helpers::net::parse_ipv4_addr(u32::from_be(s))?,
                dst: helpers::net::parse_ipv4_addr(u32::from_be(d))?,
                version: CtIpVersion::V4,
            };
            (orig, reply)
        } else if flags & RETIS_CT_IPV6 != 0 {
            let s = unsafe { raw.orig.src.addr.ipv6 };
            let d = unsafe { raw.orig.dst.addr.ipv6 };
            let orig = CtIp {
                src: format!("{}", Ipv6Addr::from(u128::from_be_bytes(s))),
                dst: format!("{}", Ipv6Addr::from(u128::from_be_bytes(d))),
                version: CtIpVersion::V6,
            };
            let s = unsafe { raw.reply.src.addr.ipv6 };
            let d = unsafe { raw.reply.dst.addr.ipv6 };
            let reply = CtIp {
                src: format!("{}", Ipv6Addr::from(u128::from_be_bytes(s))),
                dst: format!("{}", Ipv6Addr::from(u128::from_be_bytes(d))),
                version: CtIpVersion::V6,
            };
            (orig, reply)
        } else {
            bail!("ct: invalid ip tuple information");
        };

        let (orig_proto, reply_proto) = if flags & RETIS_CT_PROTO_TCP != 0 {
            (
                CtProto::Tcp {
                    tcp: CtTcp {
                        sport: u16::from_be(raw.orig.src.data),
                        dport: u16::from_be(raw.orig.dst.data),
                    },
                },
                CtProto::Tcp {
                    tcp: CtTcp {
                        sport: u16::from_be(raw.reply.src.data),
                        dport: u16::from_be(raw.reply.dst.data),
                    },
                },
            )
        } else if flags & RETIS_CT_PROTO_UDP != 0 {
            (
                CtProto::Udp {
                    udp: CtUdp {
                        sport: u16::from_be(raw.orig.src.data),
                        dport: u16::from_be(raw.orig.dst.data),
                    },
                },
                CtProto::Udp {
                    udp: CtUdp {
                        sport: u16::from_be(raw.reply.src.data),
                        dport: u16::from_be(raw.reply.dst.data),
                    },
                },
            )
        } else if flags & RETIS_CT_PROTO_ICMP != 0 {
            (
                CtProto::Icmp {
                    icmp: CtIcmp {
                        code: raw.orig.dst.data as u8,
                        r#type: (raw.orig.dst.data >> 8) as u8,
                        id: u16::from_be(raw.orig.src.data),
                    },
                },
                CtProto::Icmp {
                    icmp: CtIcmp {
                        code: raw.reply.dst.data as u8,
                        r#type: (raw.reply.dst.data >> 8) as u8,
                        id: u16::from_be(raw.reply.src.data),
                    },
                },
            )
        } else {
            bail!("ct: invalid protocol tuple information");
        };

        let tcp_state = if flags & RETIS_CT_PROTO_TCP != 0 {
            match self.tcp_states.get(&(raw.tcp_state as i32)) {
                Some(r) => Some(r.clone()),
                None => Some(format!("{}", raw.tcp_state)),
            }
        } else {
            None
        };

        let labels = U128::from_u128(u128::from_ne_bytes(raw.labels));

        Ok(CtConnEvent {
            zone_id: raw.zone_id,
            zone_dir,
            orig: CtTuple {
                ip: orig_ip,
                proto: orig_proto,
            },
            reply: CtTuple {
                ip: reply_ip,
                proto: reply_proto,
            },
            tcp_state,
            mark: if self.mark_available {
                Some(raw.mark)
            } else {
                None
            },
            labels: if self.labels_available && labels.bits() != 0 {
                Some(labels)
            } else {
                None
            },
        })
    }
}

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use super::*;
    use crate::{benchmark::helpers::*, core::events::FactoryId};

    impl RawSectionBuilder for ct_meta_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = ct_meta_event::default();
            build_raw_section(
                out,
                FactoryId::Ct as u8,
                SECTION_META as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }

    impl RawSectionBuilder for ct_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = ct_event {
                flags: RETIS_CT_DIR_REPLY | RETIS_CT_IPV4 | RETIS_CT_PROTO_TCP,
                ..Default::default()
            };
            build_raw_section(
                out,
                FactoryId::Ct as u8,
                SECTION_BASE_CONN as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }
}
