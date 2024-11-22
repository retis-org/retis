use anyhow::Result;

use crate::{
    collect::{
        collector::{ct::*, nft::*, ovs::*, skb::*, skb_drop::*, skb_tracking::*},
        Collector,
    },
    core::{
        events::{CommonEventFactory, FactoryId, SectionFactories},
        probe::{kernel::KernelEventFactory, user::UserEventFactory},
    },
};

/// Return the registered EventSectionFactories in a HashMap.
pub(crate) fn section_factories() -> Result<SectionFactories> {
    let mut factories = SectionFactories::new();

    factories.insert(FactoryId::Common, Box::<CommonEventFactory>::default());
    factories.insert(FactoryId::Kernel, Box::<KernelEventFactory>::default());
    factories.insert(FactoryId::Userspace, Box::<UserEventFactory>::default());
    factories.insert(
        FactoryId::SkbTracking,
        Box::<SkbTrackingEventFactory>::default(),
    );
    factories.insert(FactoryId::SkbDrop, Box::new(SkbDropEventFactory::new()?));
    factories.insert(FactoryId::Skb, Box::<SkbEventFactory>::default());
    factories.insert(FactoryId::Ovs, Box::new(OvsEventFactory::new()?));
    factories.insert(FactoryId::Nft, Box::<NftEventFactory>::default());
    factories.insert(FactoryId::Ct, Box::new(CtEventFactory::new()?));

    Ok(factories)
}

/// Return a list of all types known by the collectors.
pub(crate) fn get_known_types() -> Result<Vec<&'static str>> {
    let mut known_types = Vec::new();

    known_types.append(
        &mut SkbTrackingCollector::new()?
            .known_kernel_types()
            .unwrap_or_default(),
    );
    known_types.append(
        &mut SkbCollector::new()?
            .known_kernel_types()
            .unwrap_or_default(),
    );
    known_types.append(
        &mut SkbDropCollector::new()?
            .known_kernel_types()
            .unwrap_or_default(),
    );
    known_types.append(
        &mut OvsCollector::new()?
            .known_kernel_types()
            .unwrap_or_default(),
    );
    known_types.append(
        &mut NftCollector::new()?
            .known_kernel_types()
            .unwrap_or_default(),
    );
    known_types.append(&mut CtCollector::new()?.known_kernel_types().unwrap_or_default());

    Ok(known_types)
}
