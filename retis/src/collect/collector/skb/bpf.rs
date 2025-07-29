//! Rust<>BPF types definitions for the skb module. Fields are not translated in
//! the BPF part and can be represented in various orders, depending from where
//! they come from. Some handling might be needed in the unmarshalers.
//!
//! Please keep this file in sync with its BPF counterpart in bpf/skb_hook.bpf.c

use anyhow::{bail, Result};

use crate::{
    bindings::{if_vlan_uapi::*, skb_hook_uapi::*},
    core::events::{
        parse_raw_section, BpfRawSection, EventSectionFactory, FactoryId, RawEventSectionFactory,
    },
    event_section_factory,
    events::*,
};

pub(super) fn unmarshal_meta(raw_section: &BpfRawSection) -> Result<SkbMetaEvent> {
    let raw = parse_raw_section::<skb_meta_event>(raw_section)?;

    Ok(SkbMetaEvent {
        len: raw.len,
        data_len: raw.data_len,
        hash: raw.hash,
        ip_summed: raw.ip_summed,
        csum: raw.csum,
        csum_level: raw.csum_level,
        priority: raw.priority,
    })
}

pub(super) fn unmarshal_vlan(raw_section: &BpfRawSection) -> Result<SkbVlanAccelEvent> {
    let raw = parse_raw_section::<skb_vlan_event>(raw_section)?;

    Ok(SkbVlanAccelEvent {
        proto: raw.proto,
        pcp: raw.pcp,
        dei: raw.dei == 1,
        vid: raw.vid,
    })
}

pub(super) fn unmarshal_data_ref(raw_section: &BpfRawSection) -> Result<SkbDataRefEvent> {
    let raw = parse_raw_section::<skb_data_ref_event>(raw_section)?;

    Ok(SkbDataRefEvent {
        nohdr: raw.nohdr == 1,
        cloned: raw.cloned == 1,
        fclone: raw.fclone,
        users: raw.users,
        dataref: raw.dataref,
    })
}

pub(super) fn unmarshal_gso(raw_section: &BpfRawSection) -> Result<SkbGsoEvent> {
    let raw = parse_raw_section::<skb_gso_event>(raw_section)?;

    Ok(SkbGsoEvent {
        flags: raw.flags,
        frags: raw.nr_frags,
        size: raw.gso_size,
        segs: raw.gso_segs,
        r#type: raw.gso_type,
    })
}

pub(super) fn unmarshal_packet(raw_section: &BpfRawSection) -> Result<PacketEvent> {
    let raw = parse_raw_section::<skb_packet_event>(raw_section)?;

    Ok(PacketEvent {
        len: raw.len,
        capture_len: raw.capture_len,
        data: RawPacket(raw.packet[..(raw.capture_len as usize)].to_vec()),
    })
}

#[derive(Default)]
#[event_section_factory(FactoryId::Skb)]
pub(crate) struct SkbEventFactory {}

impl RawEventSectionFactory for SkbEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>, event: &mut Event) -> Result<()> {
        let mut skb: Option<SkbEvent> = None;

        for section in raw_sections.iter() {
            match section.header.data_type as u32 {
                SECTION_VLAN => {
                    skb.get_or_insert_default().vlan_accel = Some(unmarshal_vlan(section)?)
                }
                SECTION_META => skb.get_or_insert_default().meta = Some(unmarshal_meta(section)?),
                SECTION_DATA_REF => {
                    skb.get_or_insert_default().data_ref = Some(unmarshal_data_ref(section)?)
                }
                SECTION_GSO => skb.get_or_insert_default().gso = Some(unmarshal_gso(section)?),
                SECTION_PACKET => event.packet = Some(unmarshal_packet(section)?),
                x => bail!("Unknown data type ({x})"),
            }
        }

        event.skb = skb;
        Ok(())
    }
}

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use super::*;
    use crate::{benchmark::helpers::*, core::events::FactoryId};

    impl RawSectionBuilder for skb_packet_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self {
                len: 66,
                capture_len: 66,
                packet: [
                    46, 137, 59, 254, 34, 122, 42, 186, 90, 193, 129, 79, 8, 0, 69, 0, 0, 52, 32,
                    32, 64, 0, 55, 6, 237, 160, 1, 1, 1, 1, 10, 0, 42, 2, 1, 187, 157, 12, 31, 149,
                    22, 86, 145, 251, 180, 241, 128, 17, 0, 8, 17, 72, 0, 0, 1, 1, 8, 10, 28, 109,
                    231, 120, 127, 134, 144, 92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            };
            build_raw_section(
                out,
                FactoryId::Skb as u8,
                SECTION_PACKET as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }
}
