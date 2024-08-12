use std::{collections::HashMap, fmt, str::FromStr};

use anyhow::{bail, Result};

use super::{
    ct::CtModule, nft::NftModule, ovs::OvsModule, skb::SkbModule, skb_drop::SkbDropModule,
    skb_tracking::SkbTrackingModule,
};
use crate::{
    collect::Collector,
    core::{
        events::{CommonEventFactory, EventSectionFactory, FactoryId, SectionFactories},
        probe::{kernel::KernelEventFactory, user::UserEventFactory},
    },
};

/// Module identifiers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ModuleId {
    SkbTracking,
    Skb,
    SkbDrop,
    Ovs,
    Nft,
    Ct,
}

impl ModuleId {
    /// Converts a ModuleId to a section unique str identifier.
    pub fn to_str(self) -> &'static str {
        use ModuleId::*;
        match self {
            SkbTracking => "skb-tracking",
            SkbDrop => "skb-drop",
            Skb => "skb",
            Ovs => "ovs",
            Nft => "nft",
            Ct => "ct",
        }
    }
}

impl FromStr for ModuleId {
    type Err = anyhow::Error;

    /// Constructs a ModuleId from a section unique str identifier.
    fn from_str(val: &str) -> Result<Self> {
        use ModuleId::*;
        Ok(match val {
            "skb-tracking" => SkbTracking,
            "skb-drop" => SkbDrop,
            "skb" => Skb,
            "ovs" => Ovs,
            "nft" => Nft,
            "ct" => Ct,
            x => bail!("Can't construct a ModuleId from {}", x),
        })
    }
}

// Allow using ModuleId in log messages.
impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Trait that must be implemented by Modules
pub(crate) trait Module {
    /// Return a Collector used for collect command
    fn collector(&mut self) -> &mut dyn Collector;
    /// Return an EventSectionFactory, if any
    fn section_factory(&self) -> Result<Option<Box<dyn EventSectionFactory>>> {
        Ok(None)
    }
}

/// All modules are registered there. The following is the main API and object
/// to manipulate them.
pub(crate) struct Modules {
    /// Set of registered modules we can use.
    modules: HashMap<ModuleId, Box<dyn Module>>,
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
    pub(crate) fn register(&mut self, id: ModuleId, module: Box<dyn Module>) -> Result<&mut Self> {
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
    pub(crate) fn collectors(&mut self) -> HashMap<&ModuleId, &mut dyn Collector> {
        self.modules
            .iter_mut()
            .map(|(id, m)| (id, m.collector()))
            .collect()
    }

    /// Get a specific collector, if found in the registered modules.
    pub(crate) fn get_collector(&mut self, id: &ModuleId) -> Option<&mut dyn Collector> {
        self.modules.get_mut(id).map(|m| m.collector())
    }

    /// Return the registered EventSectionFactories in a HashMap.
    pub(crate) fn section_factories(&self) -> Result<SectionFactories> {
        let mut section_factories: SectionFactories = HashMap::new();

        // Register core event sections.
        section_factories.insert(FactoryId::Common, Box::<CommonEventFactory>::default());
        section_factories.insert(FactoryId::Kernel, Box::<KernelEventFactory>::default());
        section_factories.insert(FactoryId::Userspace, Box::<UserEventFactory>::default());

        for (_, module) in self.modules.iter() {
            if let Some(factory) = module.section_factory()? {
                section_factories.insert(FactoryId::from_u8(factory.id())?, factory);
            }
        }
        Ok(section_factories)
    }
}

pub(crate) fn get_modules() -> Result<Modules> {
    let mut group = Modules::new()?;

    // Register all collectors here.
    group
        .register(ModuleId::SkbTracking, Box::new(SkbTrackingModule::new()?))?
        .register(ModuleId::Skb, Box::new(SkbModule::new()?))?
        .register(ModuleId::SkbDrop, Box::new(SkbDropModule::new()?))?
        .register(ModuleId::Ovs, Box::new(OvsModule::new()?))?
        .register(ModuleId::Nft, Box::new(NftModule::new()?))?
        .register(ModuleId::Ct, Box::new(CtModule::new()?))?;

    Ok(group)
}

#[cfg(test)]
mod tests {
    #[test]
    fn get_modules() {
        assert!(super::get_modules().is_ok());
    }
}
