use std::collections::HashMap;

use anyhow::Result;
use log::warn;

use crate::bindings::skb_drop_hook_uapi::skb_drop_event;

// Keep in sync with definition in include/net/dropreason-core.h (Linux
// sources).
const SKB_DROP_REASON_SUBSYS_SHIFT: u32 = 16;

use crate::{
    core::events::{
        parse_enum, parse_single_raw_section, BpfRawSection, EventSectionFactory, FactoryId,
        RawEventSectionFactory,
    },
    event_section_factory,
    events::*,
};

/// Per-subsystem drop reason definitions.
pub(crate) struct DropReasons {
    /// Sub-system name, if any.
    subsys_name: Option<String>,
    /// Sub-system custom drop reasons. Map of the drop reason values (i32) to
    /// their names.
    reasons: HashMap<u32, String>,
}

impl DropReasons {
    /// Construct a DropReason given a sub-system name. The name has to match
    /// the values of `enum skb_drop_reason_subsys` in include/net/dropreason.h
    /// (Linux sources) without the `SKB_DROP_REASON_SUBSYS_` prefix.
    fn from_subsystem(name: &str) -> Result<Self> {
        let subsys_name = name.to_lowercase();
        let reasons = match subsys_name.as_str() {
            "core" => parse_enum("skb_drop_reason", &["SKB_", "DROP_REASON_"])?,
            "mac80211_unusable" => parse_enum("mac80211_drop_reason", &[])?,
            "mac80211_monitor" => parse_enum("mac80211_drop_reason", &[])?,
            "openvswitch" => parse_enum("ovs_drop_reason", &[])?,
            x => {
                warn!("Unknown drop reason subsystem ({x})");
                HashMap::new()
            }
        };

        Ok(Self {
            subsys_name: match subsys_name.as_str() {
                "core" => None,
                _ => Some(subsys_name),
            },
            reasons,
        })
    }
}

#[event_section_factory(FactoryId::SkbDrop)]
pub(crate) struct SkbDropEventFactory {
    /// Map of sub-system reason ids to their custom drop reason definitions.
    reasons: HashMap<u16, DropReasons>,
}

impl RawEventSectionFactory for SkbDropEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let raw = parse_single_raw_section::<skb_drop_event>(&raw_sections)?;

        let drop_reason = raw.drop_reason;
        let (subsys, drop_reason) = self.get_reason(drop_reason);

        Ok(Box::new(SkbDropEvent {
            subsys,
            drop_reason,
        }))
    }
}

impl SkbDropEventFactory {
    /// Initialize a new skb drop factory.
    pub(crate) fn new() -> Result<Self> {
        let subsys = parse_enum("skb_drop_reason_subsys", &["SKB_DROP_REASON_SUBSYS_"])?;

        // Parse each sub-system drop reasons.
        let mut reasons = HashMap::new();

        if !subsys.is_empty() {
            subsys.iter().try_for_each(|(id, name)| -> Result<()> {
                if name != "NUM" {
                    reasons.insert(*id as u16, DropReasons::from_subsystem(name)?);
                }
                Ok(())
            })?;
        } else {
            // Legacy skb drop reasons: non-core reasons are not supported in
            // this older kernel.
            reasons.insert(0, DropReasons::from_subsystem("core")?);
        }

        Ok(Self { reasons })
    }

    /// Converts a raw drop reason value to a tuple of an optional sub-system
    /// name and a string representation of the drop reason.
    fn get_reason(&self, raw_val: i32) -> (Option<String>, String) {
        // Special case when drop reasons aren't supported by the kernel. Fake a
        // core NOT_SPECIFIED reason.
        if raw_val < 0 {
            return (None, "NOT_SPECIFIED".to_string());
        }
        let raw_val = raw_val as u32;

        // Retrieve the sub-system drop reason definition, if any.
        let subsys_id = (raw_val >> SKB_DROP_REASON_SUBSYS_SHIFT) as u16;
        let subsys = match self.reasons.get(&subsys_id) {
            Some(subsys) => subsys,
            // Handle the None case but really that should not happen, because
            // that means having a sub-system generating drop reasons without
            // being defined in the sub-systems list.
            None => {
                warn!("Unknown drop reason subsystem id ({subsys_id})");
                return (Some(subsys_id.to_string()), raw_val.to_string());
            }
        };

        // Looks genuine, generate a proper (subsys, drop reason) tuple.
        (
            subsys.subsys_name.clone(),
            match subsys.reasons.get(&raw_val) {
                Some(reason) => reason.clone(),
                None => raw_val.to_string(),
            },
        )
    }
}
