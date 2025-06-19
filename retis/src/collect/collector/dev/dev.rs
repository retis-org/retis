use std::sync::Arc;

use anyhow::Result;

use super::dev_hook;
use crate::{
    bindings::dev_hook_uapi::*,
    collect::{cli::Collect, Collector},
    core::{
        events::*,
        probe::{manager::ProbeBuilderManager, Hook},
    },
    event_section_factory,
    events::*,
};

#[derive(Default)]
pub(crate) struct DevCollector {}

impl Collector for DevCollector {
    fn new() -> Result<Self> {
        Ok(Self::default())
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct net_device *", "struct sk_buff *"])
    }

    fn init(
        &mut self,
        _: &Collect,
        probes: &mut ProbeBuilderManager,
        _: Arc<RetisEventsFactory>,
        _: &mut SectionFactories,
    ) -> Result<()> {
        probes.register_kernel_hook(Hook::from(dev_hook::DATA))
    }
}

#[event_section_factory(FactoryId::Dev)]
#[derive(Default)]
pub(crate) struct DevEventFactory {}

impl RawEventSectionFactory for DevEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>, event: &mut Event) -> Result<()> {
        let raw = parse_single_raw_section::<dev_event>(&raw_sections)?;

        // Retrieving information from `skb->dev` is tricky as this is inside an
        // union and there is no way we can know of the data is valid. Try our best
        // below to report an empty section if the data does not look like what it
        // should.
        let dev_name = match str::from_utf8(&raw.dev_name) {
            Ok(s) => s.trim_end_matches(char::from(0)),
            Err(_) => return Ok(()),
        };

        // Not much more we can do, construct the event section.
        event.dev = Some(DevEvent {
            name: dev_name.to_string(),
            ifindex: raw.ifindex,
            rx_ifindex: Some(raw.iif).filter(|iif| *iif > 0),
        });

        Ok(())
    }
}

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use super::*;
    use crate::{benchmark::helpers::*, core::events::FactoryId};

    impl RawSectionBuilder for dev_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self {
                dev_name: [
                    b'e', b't', b'h', b'0', b'\0', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                ..Default::default()
            };
            build_raw_section(out, FactoryId::Dev as u8, 0, &mut as_u8_vec(&data));
            Ok(())
        }
    }
}
