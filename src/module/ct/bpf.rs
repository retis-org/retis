//! Rust<>BPF types definitions for the ct module.
//! Please keep this file in sync with its BPF counterpart in bpf/ct.bpf.c
use anyhow::Result;
use plain::Plain;

use super::*;
use crate::{
    core::events::bpf::{parse_single_raw_section, BpfRawSection},
    module::ModuleId,
};

/// Retis-specific flags.
pub(super) const RETIS_CT_DIR_ORIG: u32 = 1 << 0;
pub(super) const RETIS_CT_DIR_REPLY: u32 = 1 << 1;

#[derive(Default)]
#[repr(C, packed)]
struct RawCtEvent {
    flags: u32,
    zone_id: u16,
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

    Ok(CtEvent {
        zone_id: raw.zone_id,
        zone_dir,
    })
}
