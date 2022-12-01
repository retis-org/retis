use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use log::warn;

use super::{cli::Collect, Collector};
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    core::{
        events::{bpf::BpfEvents, Event},
        probe,
    },
};

/// Group of collectors. Used to handle a set of collectors and to perform
/// group actions.
pub(crate) struct Group {
    list: HashMap<String, Box<dyn Collector>>,
    kernel: probe::Kernel,
    events: BpfEvents,
}

impl Group {
    pub(in crate::collector) fn new() -> Result<Group> {
        let events = BpfEvents::new()?;
        let kernel = probe::Kernel::new(&events)?;

        Ok(Group {
            list: HashMap::new(),
            kernel,
            events,
        })
    }

    /// Register a collector to the group.
    ///
    /// ```
    /// group
    ///     .register(Box::new(FirstCollector::new()?))?
    ///     .register(Box::new(SecondCollector::new()?))?
    ///     .register(Box::new(ThirdCollector::new()?))?;
    /// ```
    pub(in crate::collector) fn register(
        &mut self,
        collector: Box<dyn Collector>,
    ) -> Result<&mut Self> {
        let name = String::from(collector.name());

        // Ensure uniqueness of the collector name. This is important as their
        // name is used as a key.
        if self.list.get(&name).is_some() {
            bail!(
                "Could not insert collector '{}'; name already registered",
                name
            );
        }

        self.list.insert(name, collector);
        Ok(self)
    }

    /// Initialize all collectors by calling their `init()` function. Collectors
    /// failing to initialize will be removed from the group.
    pub(crate) fn init(&mut self, cli: &CliConfig) -> Result<()> {
        let collect = cli
            .subcommand
            .as_any()
            .downcast_ref::<Collect>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?;

        probe::common::set_ebpf_debug(collect.args()?.ebpf_debug.unwrap_or(false))?;

        // Try initializing all collectors in the group.
        for name in &collect.args()?.collectors {
            let c = self
                .list
                .get_mut(name)
                .ok_or_else(|| anyhow!("unknown collector: {}", &name))?;
            if let Err(e) = c.init(cli, &mut self.kernel, &mut self.events) {
                bail!("Could not initialize the {} collector: {}", c.name(), e);
            }
        }

        Ok(())
    }

    /// Register all collectors' command line arguments by calling their register_cli function.
    pub(crate) fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        for (_, c) in self.list.iter() {
            // Cli registration errors are fatal.
            c.register_cli(cmd)?;
        }
        Ok(())
    }

    /// Poll an event from the events channel. This is a blocking call.
    pub(crate) fn poll_event(&self) -> Result<Event> {
        self.events.poll()
    }

    /// Start the event retrieval for all collectors in the group by calling
    /// their `start()` function. Collectors failing to start the event
    /// retrieval will be kept in the group.
    pub(crate) fn start(&mut self, _: &CliConfig) -> Result<()> {
        self.events.start_polling()?;
        self.kernel.attach()?;

        for (_, c) in self.list.iter_mut() {
            if c.start().is_err() {
                warn!("Could not start '{}'", c.name());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{MainConfig, SubCommand};

    struct DummyCollectorA;
    struct DummyCollectorB;

    impl Collector for DummyCollectorA {
        fn new() -> Result<DummyCollectorA> {
            Ok(DummyCollectorA)
        }
        fn name(&self) -> &'static str {
            "dummy-a"
        }
        fn register_cli(&self, _: &mut DynamicCommand) -> Result<()> {
            Ok(())
        }
        fn init(&mut self, _: &CliConfig, _: &mut probe::Kernel, _: &mut BpfEvents) -> Result<()> {
            Ok(())
        }
        fn start(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl Collector for DummyCollectorB {
        fn new() -> Result<DummyCollectorB> {
            Ok(DummyCollectorB)
        }
        fn name(&self) -> &'static str {
            "dummy-b"
        }
        fn register_cli(&self, _: &mut DynamicCommand) -> Result<()> {
            Ok(())
        }
        fn init(&mut self, _: &CliConfig, _: &mut probe::Kernel, _: &mut BpfEvents) -> Result<()> {
            bail!("Could not initialize")
        }
        fn start(&mut self) -> Result<()> {
            bail!("Could not start");
        }
    }

    #[test]
    fn register_collectors() -> Result<()> {
        let mut group = Group::new()?;
        assert!(group.register(Box::new(DummyCollectorA::new()?)).is_ok());
        assert!(group.register(Box::new(DummyCollectorB::new()?)).is_ok());
        Ok(())
    }

    #[test]
    fn register_uniqueness() -> Result<()> {
        let mut group = Group::new()?;
        assert!(group.register(Box::new(DummyCollectorA::new()?)).is_ok());
        assert!(group.register(Box::new(DummyCollectorA::new()?)).is_err());
        Ok(())
    }

    #[test]
    fn init_collectors() -> Result<()> {
        let config = CliConfig {
            main_config: MainConfig::default(),
            subcommand: Box::new(Collect::new()?),
        };
        let mut group = Group::new()?;
        let mut dummy_a = Box::new(DummyCollectorA::new()?);
        let mut dummy_b = Box::new(DummyCollectorB::new()?);

        group.register(Box::new(DummyCollectorA::new()?))?;
        group.register(Box::new(DummyCollectorB::new()?))?;

        let mut events = BpfEvents::new()?;
        let mut kernel = probe::Kernel::new(&events)?;

        assert!(dummy_a.init(&config, &mut kernel, &mut events).is_ok());
        assert!(dummy_b.init(&config, &mut kernel, &mut events).is_err());
        assert!(group.init(&config).is_ok());
        Ok(())
    }

    #[test]
    fn start_collectors() -> Result<()> {
        let config = CliConfig {
            main_config: MainConfig::default(),
            subcommand: Box::new(Collect::new()?),
        };
        let mut group = Group::new()?;
        let mut dummy_a = Box::new(DummyCollectorA::new()?);
        let mut dummy_b = Box::new(DummyCollectorB::new()?);

        group.register(Box::new(DummyCollectorA::new()?))?;
        group.register(Box::new(DummyCollectorB::new()?))?;

        assert!(dummy_a.start().is_ok());
        assert!(dummy_b.start().is_err());
        assert!(group.start(&config).is_ok());
        Ok(())
    }
}
