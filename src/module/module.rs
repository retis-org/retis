use std::{collections::HashMap, fmt};

use anyhow::{bail, Result};

use super::{
    ovs::{OvsCollector, OvsEvent},
    skb::{SkbCollector, SkbEvent},
    skb_drop::{SkbDropCollector, SkbDropEvent},
    skb_tracking::{SkbTrackingCollector, SkbTrackingEvent},
};
use crate::{
    collect::Collector,
    core::{
        events::{bpf::CommonEvent, *},
        probe::{kernel::KernelEvent, user::UserEvent},
    },
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
        }
    }
}

// Allow using ModuleId in log messages.
impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// All modules are registered there. The following is the main API and object
/// to manipulate them.
pub(crate) struct Modules {
    /// Set of registered modules we can use.
    pub(crate) modules: HashMap<ModuleId, Box<dyn Collector>>,
    /// Factory used to retrieve events.
    pub(crate) factory: Box<dyn EventFactory>,
    /// Event section factories to parse sections into an event. Section
    /// factories come from modules. They are under an Option to allow ownership
    /// change so they can be consumed by the event factory (and moved to a
    /// processing thread).
    pub(crate) section_factories: Option<HashMap<ModuleId, Box<dyn EventSectionFactory>>>,
}

impl Modules {
    pub(crate) fn new(factory: Box<dyn EventFactory>) -> Result<Modules> {
        let mut section_factories: HashMap<ModuleId, Box<dyn EventSectionFactory>> = HashMap::new();

        section_factories.insert(ModuleId::Common, Box::<CommonEvent>::default());
        section_factories.insert(ModuleId::Kernel, Box::<KernelEvent>::default());
        section_factories.insert(ModuleId::Userspace, Box::<UserEvent>::default());

        Ok(Modules {
            modules: HashMap::new(),
            factory,
            section_factories: Some(section_factories),
        })
    }

    /// Register a collector to the group.
    ///
    /// ```
    /// modules
    ///     .register(
    ///         Box::new(FirstCollector::new()?,
    ///         Box::<FirstEvent>::default()))?,
    ///     )?
    ///     .register(
    ///         Box::new(SecondCollector::new()?,
    ///         Box::<SecondEvent>::default()))?,
    ///     )?;
    /// ```
    pub(crate) fn register(
        &mut self,
        id: ModuleId,
        collector: Box<dyn Collector>,
        section_factory: Box<dyn EventSectionFactory>,
    ) -> Result<&mut Self> {
        // Ensure uniqueness of the collector name. This is important as their
        // name is used as a key.
        if self.modules.get(&id).is_some() {
            bail!(
                "Could not insert collector '{}'; name already registered",
                id,
            );
        }

        match &mut self.section_factories {
            Some(factories) => factories.insert(id, section_factory),
            None => bail!("Section factories map no found"),
        };

        self.modules.insert(id, collector);
        Ok(self)
    }

    /// Start the event retrieval in the factory.
    pub(crate) fn start_factory(&mut self) -> Result<()> {
        let section_factories = match self.section_factories.take() {
            Some(factories) => factories,
            None => bail!("No section factory found, aborting"),
        };

        self.factory.start(section_factories)
    }

    /// Sometimes we need to perform actions on factories at a higher level.
    /// It's a bit of an hack for now, it would be good to remove it. One option
    /// would be to move the core EventSection and their factories into modules
    /// directly (using mandatory modules). This should not affect the module
    /// API though, so it should be fine as-is for now.
    #[cfg(not(test))]
    pub(crate) fn get_section_factory<T: EventSectionFactory + 'static>(
        &mut self,
        id: ModuleId,
    ) -> Result<Option<&mut T>> {
        match self.section_factories.as_mut() {
            Some(section_factories) => Ok(match section_factories.get_mut(&id) {
                Some(module) => module.as_any_mut().downcast_mut::<T>(),
                None => None,
            }),
            None => bail!("Section factories were already consumed"),
        }
    }
}

pub(crate) fn get_modules(factory: Box<dyn EventFactory>) -> Result<Modules> {
    let mut group = Modules::new(factory)?;

    // Register all collectors here.
    group
        .register(
            ModuleId::SkbTracking,
            Box::new(SkbTrackingCollector::new()?),
            Box::<SkbTrackingEvent>::default(),
        )?
        .register(
            ModuleId::Skb,
            Box::new(SkbCollector::new()?),
            Box::<SkbEvent>::default(),
        )?
        .register(
            ModuleId::SkbDrop,
            Box::new(SkbDropCollector::new()?),
            Box::<SkbDropEvent>::default(),
        )?
        .register(
            ModuleId::Ovs,
            Box::new(OvsCollector::new()?),
            Box::<OvsEvent>::default(),
        )?;

    Ok(group)
}

#[cfg(test)]
mod tests {
    use crate::core::events::bpf::BpfEventsFactory;

    #[test]
    fn get_modules() {
        let factory = BpfEventsFactory::new().unwrap();
        assert!(super::get_modules(Box::new(factory)).is_ok());
    }
}
