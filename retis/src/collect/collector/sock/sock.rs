use std::sync::Arc;

use anyhow::Result;

use super::sock_hook;
use crate::{
    bindings::sock_hook_uapi::*,
    collect::{cli::Collect, Collector},
    core::{
        events::*,
        probe::{manager::ProbeBuilderManager, Hook},
    },
    event_section_factory,
    events::*,
};

#[derive(Default)]
pub(crate) struct SockCollector {}

impl Collector for SockCollector {
    fn new() -> Result<Self> {
        Ok(Self::default())
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct sock *", "struct sk_buff *"])
    }

    fn init(
        &mut self,
        _: &Collect,
        probes: &mut ProbeBuilderManager,
        _: Arc<RetisEventsFactory>,
        _: &mut SectionFactories,
    ) -> Result<()> {
        probes.register_kernel_hook(Hook::from(sock_hook::DATA))
    }
}

#[event_section_factory(FactoryId::Sock)]
pub(crate) struct SockEventFactory {}

impl RawEventSectionFactory for SockEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>, event: &mut Event) -> Result<()> {
        let raw = parse_single_raw_section::<sock_event>(&raw_sections)?;

        event.sock = Some(SockEvent { inode: raw.inode });

        Ok(())
    }
}

impl SockEventFactory {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {})
    }
}

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use super::*;
    use crate::{benchmark::helpers::*, core::events::FactoryId};

    impl RawSectionBuilder for sock_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self::default();
            build_raw_section(out, FactoryId::Sock as u8, 0, &mut as_u8_vec(&data));
            Ok(())
        }
    }
}
