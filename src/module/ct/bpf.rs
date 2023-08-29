//! Rust<>BPF types definitions for the ct module.
//! Please keep this file in sync with its BPF counterpart in bpf/ct.bpf.c
use anyhow::{bail, Result};
use plain::Plain;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;
use crate::{
    core::events::bpf::{parse_single_raw_section, BpfRawSection},
    module::ModuleId,
};

/// Retis-specific flags.
pub(super) const RETIS_CT_DIR_ORIG: u32 = 1 << 0;
pub(super) const RETIS_CT_DIR_REPLY: u32 = 1 << 1;
pub(super) const RETIS_CT_IPV4: u32 = 1 << 2;
pub(super) const RETIS_CT_IPV6: u32 = 1 << 3;
pub(super) const RETIS_CT_PROTO_TCP: u32 = 1 << 4;
pub(super) const RETIS_CT_PROTO_UDP: u32 = 1 << 5;
pub(super) const RETIS_CT_PROTO_ICMP: u32 = 1 << 6;

#[derive(Clone, Copy)]
#[repr(C, packed)]
union IP {
    ipv4: u32,
    ipv6: u128,
}

impl Default for IP {
    fn default() -> Self {
        IP { ipv6: 0 }
    }
}

#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
struct IpProto {
    addr: IP,
    data: u16,
}

#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
struct NfConnTuple {
    src: IpProto,
    dst: IpProto,
}

#[derive(Default)]
#[repr(C, packed)]
struct RawCtEvent {
    flags: u32,
    zone_id: u16,
    orig: NfConnTuple,
    reply: NfConnTuple,
    state: u8,
}

unsafe impl Plain for RawCtEvent {}

pub(super) fn unmarshal_ct(sections: Vec<BpfRawSection>) -> Result<CtEvent> {
    let raw = parse_single_raw_section::<RawCtEvent>(ModuleId::Ct, sections)?;
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
            src: format!("{}", Ipv4Addr::from(u32::from_be(s))),
            dst: format!("{}", Ipv4Addr::from(u32::from_be(d))),
            version: CtIpVersion::V4,
        };
        let s = unsafe { raw.reply.src.addr.ipv4 };
        let d = unsafe { raw.reply.dst.addr.ipv4 };
        let reply = CtIp {
            src: format!("{}", Ipv4Addr::from(u32::from_be(s))),
            dst: format!("{}", Ipv4Addr::from(u32::from_be(d))),
            version: CtIpVersion::V4,
        };
        (orig, reply)
    } else if flags & RETIS_CT_IPV6 != 0 {
        let s = unsafe { raw.orig.src.addr.ipv6 };
        let d = unsafe { raw.orig.dst.addr.ipv6 };
        let orig = CtIp {
            src: format!("{}", Ipv6Addr::from(u128::from_be(s))),
            dst: format!("{}", Ipv6Addr::from(u128::from_be(d))),
            version: CtIpVersion::V6,
        };
        let s = unsafe { raw.reply.src.addr.ipv6 };
        let d = unsafe { raw.reply.dst.addr.ipv6 };
        let reply = CtIp {
            src: format!("{}", Ipv6Addr::from(u128::from_be(s))),
            dst: format!("{}", Ipv6Addr::from(u128::from_be(d))),
            version: CtIpVersion::V6,
        };
        (orig, reply)
    } else {
        bail!("ct: invalid protocol tuple information");
    };

    let (orig_proto, reply_proto) = if flags & RETIS_CT_PROTO_TCP != 0 {
        (
            CtProto::Tcp(CtTcp {
                sport: u16::from_be(raw.orig.src.data),
                dport: u16::from_be(raw.orig.dst.data),
            }),
            CtProto::Tcp(CtTcp {
                sport: u16::from_be(raw.reply.src.data),
                dport: u16::from_be(raw.reply.dst.data),
            }),
        )
    } else if flags & RETIS_CT_PROTO_UDP != 0 {
        (
            CtProto::Udp(CtUdp {
                sport: u16::from_be(raw.orig.src.data),
                dport: u16::from_be(raw.orig.dst.data),
            }),
            CtProto::Udp(CtUdp {
                sport: u16::from_be(raw.reply.src.data),
                dport: u16::from_be(raw.reply.dst.data),
            }),
        )
    } else if flags & RETIS_CT_PROTO_ICMP != 0 {
        (
            CtProto::Icmp(CtIcmp {
                code: raw.orig.dst.data as u8,
                r#type: (raw.orig.dst.data >> 8) as u8,
                id: u16::from_be(raw.orig.src.data),
            }),
            CtProto::Icmp(CtIcmp {
                code: raw.reply.dst.data as u8,
                r#type: (raw.reply.dst.data >> 8) as u8,
                id: u16::from_be(raw.reply.src.data),
            }),
        )
    } else {
        bail!("ct: invalid protocol tuple information");
    };

    let raw_state = raw.state;
    // These values must be kept in sync with the ones defined in:
    // include/uapi/linux/netfilter/nf_conntrack_common.h
    use CtState::*;
    let state = match raw_state {
        0 => Established,
        1 => Related,
        2 => New,
        3 => Reply,
        4 => RelatedReply,
        7 => Untracked,
        _ => bail!("ct: unsupported ct state {}", raw_state),
    };

    Ok(CtEvent {
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
        state,
    })
}
