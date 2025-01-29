use std::sync::Arc;

use anyhow::Result;

use super::tracking_hook;
use crate::{
    bindings::tracking_hook_uapi::skb_tracking_event,
    collect::{cli::Collect, Collector},
    core::{
        events::*,
        probe::{manager::ProbeBuilderManager, Hook},
    },
    event_section_factory,
    events::*,
};

#[derive(Default)]
pub(crate) struct SkbTrackingCollector {}

impl Collector for SkbTrackingCollector {
    fn new() -> Result<Self> {
        Ok(Self::default())
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct sk_buff *"])
    }

    fn init(
        &mut self,
        _: &Collect,
        probes: &mut ProbeBuilderManager,
        _: Arc<RetisEventsFactory>,
    ) -> Result<()> {
        probes.register_kernel_hook(Hook::from(tracking_hook::DATA))
    }
}

#[event_section_factory(FactoryId::SkbTracking)]
#[derive(Default)]
pub(crate) struct SkbTrackingEventFactory {}

impl RawEventSectionFactory for SkbTrackingEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        // Both raw event and actual event map 1:1 but we still want
        // to keep the bindings for consistency
        let raw = parse_single_raw_section::<skb_tracking_event>(&raw_sections)?;

        Ok(Box::new(SkbTrackingEvent {
            orig_head: raw.orig_head,
            timestamp: raw.timestamp,
            skb: raw.skb,
        }))
    }
}

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use crate::{
        benchmark::helpers::*, bindings::tracking_hook_uapi::skb_tracking_event,
        core::events::FactoryId,
    };

    impl RawSectionBuilder for skb_tracking_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self::default();
            build_raw_section(out, FactoryId::SkbTracking as u8, 0, &mut as_u8_vec(&data));
            Ok(())
        }
    }
}
