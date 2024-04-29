use std::collections::HashMap;

use anyhow::{bail, Result};

use super::{
    ct::CtModule, nft::NftModule, ovs::OvsModule, skb::SkbModule, skb_drop::SkbDropModule,
    skb_tracking::SkbTrackingModule,
};
use crate::{
    collect::Collector,
    core::probe::{kernel::KernelEventFactory, user::UserEventFactory},
    events::{bpf::CommonEventFactory, *},
    process::tracking::TrackingInfoEventFactory,
};

/// Trait that must be implemented by Modules
pub(crate) trait Module {
    /// Return a Collector used for collect command
    fn collector(&mut self) -> &mut dyn Collector;
    /// Return an EventSectionFactory
    fn section_factory(&self) -> Result<Box<dyn EventSectionFactory>>;
}

/// All modules are registered there. The following is the main API and object
/// to manipulate them.
pub(crate) struct Modules {
    /// Set of registered modules we can use.
    modules: HashMap<SectionId, Box<dyn Module>>,
}

impl Modules {
    pub(crate) fn new() -> Result<Modules> {
        Ok(Modules {
            modules: HashMap::new(),
        })
    }

    /// Register a module
    ///
    /// ```
    /// modules
    ///     .register(
    ///         Box::new(FirstModule::new()?,
    ///     )?
    ///     .register(
    ///         Box::new(SecondModule::new()?,
    ///     )?;
    /// ```
    pub(crate) fn register(&mut self, id: SectionId, module: Box<dyn Module>) -> Result<&mut Self> {
        // Ensure uniqueness of the module name. This is important as their
        // name is used as a key.
        if self.modules.contains_key(&id) {
            bail!("Could not insert module '{}'; name already registered", id,);
        }

        self.modules.insert(id, module);
        Ok(self)
    }

    /// Get an hashmap of all the collectors available in the registered
    /// modules.
    pub(crate) fn collectors(&mut self) -> HashMap<&SectionId, &mut dyn Collector> {
        self.modules
            .iter_mut()
            .map(|(id, m)| (id, m.collector()))
            .collect()
    }

    /// Get a specific collector, if found in the registered modules.
    pub(crate) fn get_collector(&mut self, id: &SectionId) -> Option<&mut dyn Collector> {
        self.modules.get_mut(id).map(|m| m.collector())
    }

    /// Return the registered EventSectionFactories in a HashMap.
    pub(crate) fn section_factories(&self) -> Result<SectionFactories> {
        let mut section_factories: SectionFactories = HashMap::new();

        // Register core event sections.
        section_factories.insert(SectionId::Common, Box::<CommonEventFactory>::default());
        section_factories.insert(SectionId::Kernel, Box::<KernelEventFactory>::default());
        section_factories.insert(SectionId::Userspace, Box::<UserEventFactory>::default());
        section_factories.insert(
            SectionId::Tracking,
            Box::<TrackingInfoEventFactory>::default(),
        );

        for (id, module) in self.modules.iter() {
            section_factories.insert(*id, module.section_factory()?);
        }
        Ok(section_factories)
    }
}

pub(crate) fn get_modules() -> Result<Modules> {
    let mut group = Modules::new()?;

    // Register all collectors here.
    group
        .register(SectionId::SkbTracking, Box::new(SkbTrackingModule::new()?))?
        .register(SectionId::Skb, Box::new(SkbModule::new()?))?
        .register(SectionId::SkbDrop, Box::new(SkbDropModule::new()?))?
        .register(SectionId::Ovs, Box::new(OvsModule::new()?))?
        .register(SectionId::Nft, Box::new(NftModule::new()?))?
        .register(SectionId::Ct, Box::new(CtModule::new()?))?;

    Ok(group)
}

#[cfg(test)]
mod tests {
    #[test]
    fn get_modules() {
        assert!(super::get_modules().is_ok());
    }
}
