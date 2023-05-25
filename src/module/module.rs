use std::{collections::HashMap, fmt};

use anyhow::{bail, Result};

use super::{
    ovs::OvsModule, skb::SkbModule, skb_drop::SkbDropModule, skb_tracking::SkbTrackingModule,
};
use crate::{
    collect::Collector,
    core::{
        events::{bpf::CommonEventFactory, *},
        probe::{kernel::KernelEventFactory, user::UserEventFactory},
    },
    process::tracking::TrackingInfoEventFactory,
};

/// List of unique event sections owners.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ModuleId {
    Common = 1,
    Kernel = 2,
    Userspace = 3,
    SkbTracking = 4,
    Skb = 5,
    SkbDrop = 6,
    Ovs = 7,
    Tracking = 8,
    // TODO: use std::mem::variant_count once in stable.
    _MAX = 9,
}

impl ModuleId {
    /// Constructs an ModuleId from a section unique identifier. Please
    /// keep in sync with its BPF counterpart.
    pub(crate) fn from_u8(val: u8) -> Result<ModuleId> {
        use ModuleId::*;
        Ok(match val {
            1 => Common,
            2 => Kernel,
            3 => Userspace,
            4 => SkbTracking,
            5 => Skb,
            6 => SkbDrop,
            7 => Ovs,
            8 => Tracking,
            x => bail!("Can't construct a ModuleId from {}", x),
        })
    }

    /// Converts an ModuleId to a section unique identifier. Please
    /// keep in sync with its BPF counterpart.
    #[allow(dead_code)]
    pub(crate) fn to_u8(self) -> u8 {
        use ModuleId::*;
        match self {
            Common => 1,
            Kernel => 2,
            Userspace => 3,
            SkbTracking => 4,
            Skb => 5,
            SkbDrop => 6,
            Ovs => 7,
            Tracking => 8,
            _MAX => 9,
        }
    }

    /// Constructs an ModuleId from a section unique str identifier.
    pub(crate) fn from_str(val: &str) -> Result<ModuleId> {
        use ModuleId::*;
        Ok(match val {
            "common" => Common,
            "kernel" => Kernel,
            "userspace" => Userspace,
            "skb-tracking" => SkbTracking,
            "skb" => Skb,
            "skb-drop" => SkbDrop,
            "ovs" => Ovs,
            "tracking" => Tracking,
            x => bail!("Can't construct a ModuleId from {}", x),
        })
    }

    /// Converts an ModuleId to a section unique str identifier.
    pub(crate) fn to_str(self) -> &'static str {
        use ModuleId::*;
        match self {
            Common => "common",
            Kernel => "kernel",
            Userspace => "userspace",
            SkbTracking => "skb-tracking",
            Skb => "skb",
            SkbDrop => "skb-drop",
            Ovs => "ovs",
            Tracking => "tracking",
            _MAX => "_max",
        }
    }

    /// Returns a vec of all valid variants of ModuleId.
    pub(crate) fn variants() -> Vec<ModuleId> {
        (1..ModuleId::_MAX.to_u8())
            .map(|id| Self::from_u8(id).unwrap())
            .collect()
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
    /// Return an EventSectionFactory
    fn section_factory(&self) -> Result<Box<dyn EventSectionFactory>>;
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
        if self.modules.get(&id).is_some() {
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
        section_factories.insert(ModuleId::Common, Box::<CommonEventFactory>::default());
        section_factories.insert(ModuleId::Kernel, Box::<KernelEventFactory>::default());
        section_factories.insert(ModuleId::Userspace, Box::<UserEventFactory>::default());
        section_factories.insert(
            ModuleId::Tracking,
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
        .register(ModuleId::SkbTracking, Box::new(SkbTrackingModule::new()?))?
        .register(ModuleId::Skb, Box::new(SkbModule::new()?))?
        .register(ModuleId::SkbDrop, Box::new(SkbDropModule::new()?))?
        .register(ModuleId::Ovs, Box::new(OvsModule::new()?))?;

    Ok(group)
}

#[cfg(test)]
mod tests {
    #[test]
    fn get_modules() {
        assert!(super::get_modules().is_ok());
    }
}
