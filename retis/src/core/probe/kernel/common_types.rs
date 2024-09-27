//! # Common types
//!
//! Logic to retrieve common types from our probes whenever such type is seen
//! (initial use case is as function parameter, but this could be extended to
//! struct members). This is intended for small types (eg. enums) that are not
//! found all over the place and will always very likely provide useful
//! information. They have to fit in an u64 anyway.
//!
//! Currently supported types:
//! - `enum skb_drop_reason`
//! - `enum mac80211_drop_reason`
//! - `enum ovs_drop_reason`
//! - `enum sk_rst_reason`

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use btf_rs::Type;
use log::warn;

use crate::{
    core::{
        events::{
            parse_single_raw_section, BpfRawSection, EventSectionFactory, FactoryId,
            RawEventSectionFactory,
        },
        inspect::inspector,
    },
    event_section_factory,
    events::*,
};

// Please keep in sync with its BPF counterpart.
#[repr(C)]
struct RawCommonTypeEvent {
    /// Type id of the common type retrieved.
    r#type: u32,
    /// The raw value we retrieved.
    val: u64,
}

#[derive(Eq, Hash, PartialEq)]
enum TypeId {
    SkbDropReason = 1,
    SkRstReason,
}

impl TypeId {
    fn from_u32(val: u32) -> Result<TypeId> {
        use TypeId::*;
        Ok(match val {
            1 => SkbDropReason,
            2 => SkRstReason,
            x => bail!("Cannot convert {x} to TypeId"),
        })
    }
}

#[event_section_factory(FactoryId::CommonType)]
pub(crate) struct CommonTypeEventFactory {
    // 2-step translation map of a raw value, first by its type id and then by
    // its actual value.
    types: HashMap<TypeId, HashMap<u64, String>>,
}

impl CommonTypeEventFactory {
    pub(crate) fn new() -> Result<Self> {
        let mut types = HashMap::new();

        // Drop reasons are a bit specific as multiple enum actually defines it.
        let mut drop_reasons = HashMap::new();
        drop_reasons.extend(parse_enum("skb_drop_reason", &["SKB_", "DROP_REASON_"])?);
        drop_reasons.extend(parse_enum("mac80211_drop_reason", &[])?);
        drop_reasons.extend(parse_enum("ovs_drop_reason", &[])?);
        types.insert(TypeId::SkbDropReason, drop_reasons);

        // enum sk_rst_reason
        types.insert(
            TypeId::SkRstReason,
            parse_enum("sk_rst_reason", &["SK_RST_REASON_"])?,
        );

        Ok(Self { types })
    }
}

impl RawEventSectionFactory for CommonTypeEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let raw = parse_single_raw_section::<RawCommonTypeEvent>(&raw_sections)?;

        let (r#type, map) = self
            .types
            .get_key_value(&TypeId::from_u32(raw.r#type)?)
            .ok_or_else(|| anyhow!("Could not get translation map for type {}", raw.r#type))?;

        Ok(match r#type {
            TypeId::SkbDropReason => {
                // Sub-system ids are defined in `enum skb_drop_reason_subsys`,
                // see Linux source code. We could get the below values parsing
                // the subsys enum, but that adds complexity for a tiny UX
                // improvement (the values have to be converted by hand in both
                // cases anyway).
                const SKB_DROP_REASON_SUBSYS_SHIFT: u32 = 16;
                let subsys = match raw.val >> SKB_DROP_REASON_SUBSYS_SHIFT {
                    0 => None,
                    1 => Some("mac80211_unusable".to_string()),
                    2 => Some("mac80211_monitor".to_string()),
                    3 => Some("openvswitch".to_string()),
                    x => {
                        warn!("Unknown drop reason subsystem ({x})");
                        Some(x.to_string())
                    }
                };

                Box::new(SkbDropEvent {
                    subsys,
                    drop_reason: match map.get(&raw.val) {
                        Some(reason) => reason.clone(),
                        None => raw.val.to_string(),
                    },
                })
            }
            TypeId::SkRstReason => Box::new(SkResetReasonEvent {
                reset_reason: match map.get(&raw.val) {
                    Some(reason) => reason.clone(),
                    None => raw.val.to_string(),
                },
            }),
        })
    }
}

/// Parse a BTF enum (using its name as a parameter) and convert it as an
/// HashMap<u32, String>: the u32 is the variant values, used as a key; and the
/// String is the variant name.
///
/// An option array of prefixes can be provided to trim the variant names for an
/// improved display.
fn parse_enum(r#enum: &str, trim_start: &[&str]) -> Result<HashMap<u64, String>> {
    let mut values = HashMap::new();

    if let Ok(types) = inspector()?.kernel.btf.resolve_types_by_name(r#enum) {
        if let Some((btf, Type::Enum(r#enum))) =
            types.iter().find(|(_, t)| matches!(t, Type::Enum(_)))
        {
            for member in r#enum.members.iter() {
                let mut val = btf.resolve_name(member)?;
                trim_start
                    .iter()
                    .for_each(|p| val = val.trim_start_matches(p).to_string());
                values.insert(member.val().into(), val.to_string());
            }
        } else if let Some((btf, Type::Enum64(r#enum))) =
            types.iter().find(|(_, t)| matches!(t, Type::Enum64(_)))
        {
            for member in r#enum.members.iter() {
                let mut val = btf.resolve_name(member)?;
                trim_start
                    .iter()
                    .for_each(|p| val = val.trim_start_matches(p).to_string());
                values.insert(member.val(), val.to_string());
            }
        }
    }

    Ok(values)
}
