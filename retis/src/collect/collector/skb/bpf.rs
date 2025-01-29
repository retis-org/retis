//! Rust<>BPF types definitions for the skb module. Fields are not translated in
//! the BPF part and can be represented in various orders, depending from where
//! they come from. Some handling might be needed in the unmarshalers.
//!
//! Please keep this file in sync with its BPF counterpart in bpf/skb_hook.bpf.c

use anyhow::bail;
use std::str;

use anyhow::Result;

use crate::{
    bindings::if_vlan_uapi::*,
    bindings::skb_hook_uapi::*,
    core::events::{
        parse_raw_section, BpfRawSection, EventSectionFactory, FactoryId, RawEventSectionFactory,
    },
    event_section_factory,
    events::*,
};

/// Unmarshal net device info. Can return Ok(None) in case the info does not
/// look like it's genuine (see below).
pub(super) fn unmarshal_dev(raw_section: &BpfRawSection) -> Result<Option<SkbDevEvent>> {
    let raw = parse_raw_section::<skb_netdev_event>(raw_section)?;

    // Retrieving information from `skb->dev` is tricky as this is inside an
    // union and there is no way we can know of the data is valid. Try our best
    // below to report an empty section if the data does not look like what it
    // should.
    let dev_name = match str::from_utf8(&raw.dev_name) {
        Ok(s) => s.trim_end_matches(char::from(0)),
        Err(_) => return Ok(None),
    };

    // Not much more we can do, construct the event section.
    let mut event = SkbDevEvent {
        name: dev_name.to_string(),
        ifindex: raw.ifindex,
        ..Default::default()
    };
    if raw.iif > 0 {
        event.rx_ifindex = Some(raw.iif);
    }

    Ok(Some(event))
}

pub(super) fn unmarshal_ns(raw_section: &BpfRawSection) -> Result<SkbNsEvent> {
    let raw = parse_raw_section::<skb_netns_event>(raw_section)?;

    Ok(SkbNsEvent { netns: raw.netns })
}

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

pub(super) fn unmarshal_packet(raw_section: &BpfRawSection) -> Result<SkbPacketEvent> {
    let raw = parse_raw_section::<skb_packet_event>(raw_section)?;

    Ok(SkbPacketEvent {
        len: raw.len,
        capture_len: raw.capture_len,
        packet: RawPacket(raw.packet[..(raw.capture_len as usize)].to_vec()),
    })
}

#[event_section_factory(FactoryId::Skb)]
#[derive(Default)]
pub(crate) struct SkbEventFactory {}

impl RawEventSectionFactory for SkbEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>, event: &mut Event) -> Result<()> {
        let mut skb = SkbEvent::default();

        for section in raw_sections.iter() {
            match section.header.data_type as u32 {
                SECTION_VLAN => skb.vlan_accel = Some(unmarshal_vlan(section)?),
                SECTION_DEV => skb.dev = unmarshal_dev(section)?,
                SECTION_NS => skb.ns = Some(unmarshal_ns(section)?),
                SECTION_META => skb.meta = Some(unmarshal_meta(section)?),
                SECTION_DATA_REF => skb.data_ref = Some(unmarshal_data_ref(section)?),
                SECTION_GSO => skb.gso = Some(unmarshal_gso(section)?),
                SECTION_PACKET => skb.packet = Some(unmarshal_packet(section)?),
                x => bail!("Unknown data type ({x})"),
            }
        }

        event.skb = Some(skb);
        Ok(())
    }
}

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use super::*;
    use crate::{benchmark::helpers::*, core::events::FactoryId};

    impl RawSectionBuilder for skb_netdev_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self {
                dev_name: [
                    b'e', b't', b'h', b'0', b'\0', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                ..Default::default()
            };
            build_raw_section(
                out,
                FactoryId::Skb as u8,
                SECTION_DEV as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }

    impl RawSectionBuilder for skb_netns_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self::default();
            build_raw_section(
                out,
                FactoryId::Skb as u8,
                SECTION_NS as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }

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
