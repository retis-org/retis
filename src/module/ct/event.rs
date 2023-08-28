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

/// Conntrack event
#[event_section]
pub(crate) struct CtEvent {
    /// Zone ID
    pub(crate) zone_id: u16,
    /// Zone direction
    pub(crate) zone_dir: ZoneDir,
}
impl EventFmt for CtEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
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
