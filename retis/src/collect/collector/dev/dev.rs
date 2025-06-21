use std::{collections::HashMap, sync::Arc};

use anyhow::{bail, Result};
use log::warn;

use super::*;
use crate::{
    bindings::dev_common_uapi::*,
    collect::{cli::Collect, Collector},
    core::{
        events::*,
        inspect::{inspector, kernel_version::KernelVersionReq, parse_struct},
        kernel::Symbol,
        probe::{manager::ProbeBuilderManager, Hook, Probe},
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
        // Net device data retrieval.
        probes.register_kernel_hook(Hook::from(dev_hook::DATA))?;

        // Core stats hook.
        match Symbol::from_name("netdev_core_stats_inc") {
            Ok(symbol) => {
                let mut probe = Probe::kprobe(symbol)?;
                probe.add_hook(Hook::from(core_stat_hook::DATA))?;

                probes.register_probe(probe)?;
            }
            Err(e) => {
                let kver = inspector()?.kernel.version();

                // netdev_core_stats_inc is available on 6.7+ kernels and is
                // noinline. Issue a warning if it cannot be probed.
                if KernelVersionReq::parse(">= 6.7")?.matches(kver) {
                    warn!("netdev_core_stats_inc cannot be probed: {e}");
                }
            }
        }

        Ok(())
    }
}

#[event_section_factory(FactoryId::Dev)]
#[derive(Default)]
pub(crate) struct DevEventFactory {
    // Mapping of core stats field offset to their names.
    core_stats: HashMap<u32, String>,
}

impl RawEventSectionFactory for DevEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>, event: &mut Event) -> Result<()> {
        let mut dev = DevEvent::default();

        for section in raw_sections.iter() {
            match section.header.data_type as u32 {
                SECTION_DEV => {
                    let raw = parse_raw_section::<dev_event>(section)?;

                    // Retrieving information from `skb->dev` is tricky as this is inside an
                    // union and there is no way we can know of the data is valid. Try our best
                    // below to report an empty section if the data does not look like what it
                    // should.
                    let dev_name = match str::from_utf8(&raw.dev_name) {
                        Ok(s) => s.trim_end_matches(char::from(0)),
                        Err(_) => return Ok(()),
                    };

                    // Not much more we can do, construct the event section.
                    dev.name = dev_name.to_string();
                    dev.ifindex = raw.ifindex;
                    dev.rx_ifindex = Some(raw.iif).filter(|iif| *iif > 0);
                }
                SECTION_CORE_STAT => {
                    let raw = parse_raw_section::<dev_core_stat_event>(section)?;

                    dev.core_stat = Some(match self.core_stats.get(&raw.offset) {
                        Some(name) => name.clone(),
                        None => format!("offset_{}", raw.offset),
                    });
                }
                x => bail!("Unknown data type ({x})"),
            }
        }

        event.dev = Some(dev);
        Ok(())
    }
}

impl DevEventFactory {
    pub(crate) fn new() -> Result<Self> {
        let mut core_stats = HashMap::new();

        for (offset, field) in parse_struct("net_device_core_stats")? {
            core_stats.insert(offset / 8, field);
        }

        Ok(Self { core_stats })
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
            build_raw_section(
                out,
                FactoryId::Dev as u8,
                SECTION_DEV as u8,
                &mut as_u8_vec(&data),
            );
            Ok(())
        }
    }
}
