use std::sync::Arc;

use anyhow::Result;
use btf_rs::Type;

use super::netns_hook;
use crate::{
    bindings::netns_hook_uapi::*,
    collect::{cli::Collect, Collector},
    core::{
        events::*,
        inspect::inspector,
        probe::{manager::ProbeBuilderManager, Hook},
    },
    event_section_factory,
    events::*,
};

#[derive(Default)]
pub(crate) struct NsCollector {}

impl Collector for NsCollector {
    fn new() -> Result<Self> {
        Ok(Self::default())
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec![
            "struct net *",
            "struct sk_buff *",
            "struct net_device *",
        ])
    }

    fn init(
        &mut self,
        _: &Collect,
        probes: &mut ProbeBuilderManager,
        _: Arc<RetisEventsFactory>,
        _: &mut SectionFactories,
    ) -> Result<()> {
        probes.register_kernel_hook(Hook::from(netns_hook::DATA))
    }
}

#[event_section_factory(FactoryId::Ns)]
pub(crate) struct NsEventFactory {
    // Does the kernel support net cookies?
    net_cookie: bool,
}

impl RawEventSectionFactory for NsEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>, event: &mut Event) -> Result<()> {
        let raw = parse_single_raw_section::<netns_event>(&raw_sections)?;

        event.netns = Some(NetnsEvent {
            cookie: Some(raw.cookie).filter(|_| self.net_cookie),
            inum: raw.inum,
        });

        Ok(())
    }
}

impl NsEventFactory {
    pub(crate) fn new() -> Result<Self> {
        let mut net_cookie = false;
        if let Ok(types) = inspector()?.kernel.btf.resolve_types_by_name("net") {
            if let Some((btf, Type::Struct(r#struct))) =
                types.iter().find(|(_, t)| matches!(t, Type::Struct(_)))
            {
                for member in r#struct.members.iter() {
                    let name = btf.resolve_name(member)?;
                    if name == "net_cookie" {
                        net_cookie = true;
                    }
                }
            }
        }

        Ok(Self { net_cookie })
    }
}

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use super::*;
    use crate::{benchmark::helpers::*, core::events::FactoryId};

    impl RawSectionBuilder for netns_event {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = Self::default();
            build_raw_section(out, FactoryId::Ns as u8, 0, &mut as_u8_vec(&data));
            Ok(())
        }
    }
}
