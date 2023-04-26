use std::{collections::HashSet, sync::mpsc, thread, time::Duration};

use anyhow::{anyhow, bail, Result};
use log::{error, info, warn};
use signal_hook::{consts::SIGINT, iterator::Signals};

use super::{
    cli::Collect,
    output::{get_processors, JsonFormat},
};
#[cfg(not(test))]
use crate::core::probe::kernel::{config::init_stack_map, kernel::KernelEventFactory};
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig, FullCli},
    core::{
        events::{bpf::BpfEventsFactory, EventFactory},
        filters::{
            filters::{BpfFilter, Filter},
            packets::filter::FilterPacket,
        },
        kernel::Symbol,
        probe::{self, Probe, ProbeManager},
        tracking::skb_tracking::init_tracking,
    },
    module::{get_modules, ModuleId, Modules},
};

/// Generic trait representing a collector. All collectors are required to
/// implement this, as they'll be manipulated through this trait.
pub(crate) trait Collector {
    /// Allocate and return a new instance of the collector, using only default
    /// values for its internal fields.
    fn new() -> Result<Self>
    where
        Self: Sized;
    /// List of kernel data types the collector can retrieve data from, if any.
    /// This is useful for registering dynamic collectors, and is used later for
    /// checking requested probes are not a no-op.
    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        None
    }
    ///Register command line arguments on the provided DynamicCommand object
    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()>;
    /// Initialize the collector, likely to be used to pass configuration data
    /// such as filters or command line arguments. We need to split the new &
    /// the init phase for collectors, to allow giving information to the core
    /// as part of the collector registration and only then feed the collector
    /// with data coming from the core. Checks for the mandatory part of the
    /// collector should be done here.
    ///
    /// This function should only return an Error in case it's fatal as this
    /// will make the whole program to fail. In general collectors should try
    /// hard to run in various setups, see the `crate::collector` top
    /// documentation for more information.
    fn init(&mut self, cli: &CliConfig, probes: &mut probe::ProbeManager) -> Result<()>;
    /// Start the group of events (non-probes).
    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Main collectors object and API.
pub(crate) struct Collectors {
    modules: Modules,
    probes: probe::ProbeManager,
    cli: CliConfig,
    factory: Box<dyn EventFactory>,
    known_kernel_types: HashSet<String>,
}

impl Collectors {
    #[allow(unused_mut)] // For tests.
    fn new(mut modules: Modules, mut cli: FullCli, factory: Box<dyn EventFactory>) -> Result<Self> {
        // Register all collectors' command line arguments. Cli registration
        // errors are fatal.
        let cmd = cli.get_subcommand_mut()?.dynamic_mut().unwrap();
        modules
            .collectors()
            .iter()
            .try_for_each(|(_, c)| c.register_cli(cmd))?;

        // Now we can parse all parameters.
        let cli = cli.run()?;

        #[cfg(not(test))]
        let mut probes = probe::ProbeManager::new()?;
        #[cfg(test)]
        let probes = probe::ProbeManager::new()?;

        #[cfg(not(test))]
        let sm = init_stack_map()?;
        #[cfg(not(test))]
        probes.reuse_map("stack_map", sm.fd())?;

        #[cfg(not(test))]
        match modules.get_section_factory::<KernelEventFactory>(ModuleId::Kernel)? {
            Some(kernel_factory) => kernel_factory.stack_map = Some(sm),
            None => bail!("Can't get kernel section factory"),
        }

        Ok(Collectors {
            modules,
            probes,
            known_kernel_types: HashSet::new(),
            cli,
            factory,
        })
    }

    /// Setup user defined input filter.
    fn setup_filters(probes: &mut ProbeManager, collect: &Collect) -> Result<()> {
        if let Some(f) = &collect.args()?.packet_filter {
            let fb = FilterPacket::from_string(f.to_string())?;
            probes.register_filter(Filter::Packet(BpfFilter(fb.to_bytes()?)))?;
        }

        Ok(())
    }

    /// Initialize all collectors by calling their `init()` function.
    pub(crate) fn init(&mut self) -> Result<()> {
        let collect = self
            .cli
            .subcommand
            .as_any()
            .downcast_ref::<Collect>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?;

        probe::common::set_ebpf_debug(collect.args()?.ebpf_debug)?;
        if collect.args()?.stack {
            self.probes.set_probe_opt(probe::ProbeOption::StackTrace)?;
        }

        // Try initializing all collectors.
        for name in &collect.args()?.collectors {
            let id = ModuleId::from_str(name)?;
            let c = self
                .modules
                .get_collector(&id)
                .ok_or_else(|| anyhow!("unknown collector {}", name))?;

            if let Err(e) = c.init(&self.cli, &mut self.probes) {
                bail!("Could not initialize the {} collector: {}", id, e);
            }

            // If the collector provides known kernel types, meaning we have a
            // dynamic collector, retrieve and store them for later processing.
            if let Some(kt) = c.known_kernel_types() {
                kt.into_iter().for_each(|x| {
                    self.known_kernel_types.insert(x.to_string());
                });
            }
        }

        // Initialize tracking & filters.
        if self.known_kernel_types.contains("struct sk_buff *") {
            init_tracking(&mut self.probes)?;
        }
        Self::setup_filters(&mut self.probes, collect)?;

        // Setup user defined probes.
        let mut probes = Vec::new();
        collect
            .args()?
            .probes
            .iter()
            .try_for_each(|p| -> Result<()> {
                probes.push(self.parse_probe(p)?);
                Ok(())
            })?;
        probes
            .drain(..)
            .try_for_each(|p| self.probes.add_probe(p))?;

        Ok(())
    }

    /// Start the event retrieval for all collectors by calling
    /// their `start()` function.
    pub(crate) fn start(&mut self) -> Result<()> {
        let section_factories = match self.modules.section_factories.take() {
            Some(factories) => factories,
            None => bail!("No section factory found, aborting"),
        };
        self.factory.start(section_factories)?;

        self.probes.attach()?;

        self.modules.collectors().iter_mut().for_each(|(id, c)| {
            if c.start().is_err() {
                warn!("Could not start collector '{id}'");
            }
        });

        Ok(())
    }

    /// Starts the processing loop and block until we get a single SIGINT
    /// (e.g. ctrl+c), then return after properly cleaning up. This is the main
    /// collector cmd loop.
    pub(crate) fn process(&mut self) -> Result<()> {
        let collect = self
            .cli
            .subcommand
            .as_any()
            .downcast_ref::<Collect>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?;

        // We use JSON format output for all events for now.
        let mut json = JsonFormat::default();
        let mut processors = get_processors(&mut json, collect.args()?)?;

        let mut sigint = Signals::new([SIGINT])?;
        let (txc, rxc) = mpsc::channel();

        thread::spawn(move || {
            // Only wait for a single SIGINT to let the user really interrupt us
            // in case it's needed.
            sigint.wait();
            info!("Received SIGINT, terminating...");

            if let Err(e) = txc.send(()) {
                error!(
                    "Failed to send message after receiving ctrl+c signal: {}",
                    e
                );
            }
        });

        loop {
            match self.factory.next_event(Some(Duration::from_secs(1)))? {
                Some(event) => processors
                    .iter_mut()
                    .try_for_each(|p| p.process_one(&event))?,
                None => continue,
            }

            // If we're interrupted, break the loop to allow nicely exiting.
            if rxc.try_recv().is_ok() {
                break;
            }
        }

        processors.iter_mut().try_for_each(|p| p.flush())
    }

    /// Parse a user defined probe (through cli parameters) and extract its type and
    /// target.
    fn parse_probe(&self, probe: &str) -> Result<Probe> {
        let (type_str, target) = match probe.split_once(':') {
            Some((type_str, target)) => (type_str, target),
            None => {
                info!(
                    "Invalid probe format, no TYPE given in '{}', using 'kprobe:{}'. See the help.",
                    probe, probe
                );
                ("kprobe", probe)
            }
        };

        let symbol = Symbol::from_name(target)?;

        // Check if the probe would be used by a collector to retrieve data.
        let mut valid = false;
        for r#type in self.known_kernel_types.iter() {
            if symbol.parameter_offset(r#type)?.is_some() {
                valid = true;
                break;
            }
        }
        if !valid {
            warn!(
                "A probe to symbol {} is attached but no collector will retrieve data from it, only generic information will be retrieved",
                symbol
            );
        }

        match type_str {
            "kprobe" => Ok(Probe::kprobe(symbol)?),
            "kretprobe" => Ok(Probe::kretprobe(symbol)?),
            "tp" => Ok(Probe::raw_tracepoint(symbol)?),
            x => bail!("Invalid TYPE {}. See the help.", x),
        }
    }
}

/// Allocate collectors and retrieve a group containing them, used to perform
/// batched operations. This is the primary entry point for manipulating the
/// collectors.
pub(crate) fn get_collectors(cli: FullCli) -> Result<Collectors> {
    let factory = BpfEventsFactory::new()?;
    let event_map_fd = factory.map_fd();

    let mut collectors = Collectors::new(get_modules()?, cli, Box::new(factory))?;
    collectors.probes.reuse_map("events_map", event_map_fd)?;

    Ok(collectors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cli::{MainConfig, SubCommand},
        core::events::{bpf::BpfRawSection, *},
        event_section, event_section_factory,
    };

    struct DummyCollectorA;
    struct DummyCollectorB;

    impl Collector for DummyCollectorA {
        fn new() -> Result<DummyCollectorA> {
            Ok(DummyCollectorA)
        }
        fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
            Some(vec!["struct sk_buff *", "struct net_device *"])
        }
        fn register_cli(&self, cli: &mut DynamicCommand) -> Result<()> {
            cli.register_module_noargs(ModuleId::Skb)
        }
        fn init(&mut self, _: &CliConfig, _: &mut probe::ProbeManager) -> Result<()> {
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
        fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
            None
        }
        fn register_cli(&self, cli: &mut DynamicCommand) -> Result<()> {
            cli.register_module_noargs(ModuleId::Ovs)
        }
        fn init(&mut self, _: &CliConfig, _: &mut probe::ProbeManager) -> Result<()> {
            bail!("Could not initialize")
        }
        fn start(&mut self) -> Result<()> {
            bail!("Could not start");
        }
    }

    #[event_section]
    #[event_section_factory(Self)]
    struct TestEvent {}

    impl RawEventSectionFactory for TestEvent {
        fn from_raw(&mut self, _: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
            Ok(Box::new(TestEvent::default()))
        }
    }

    fn get_config() -> Result<CliConfig> {
        Ok(CliConfig {
            main_config: MainConfig::default(),
            subcommand: Box::new(Collect::new()?),
        })
    }

    fn get_cli() -> Result<FullCli> {
        Ok(crate::cli::get_cli()?.build_from(vec!["retis", "collect"])?)
    }

    fn new_collectors(modules: Modules) -> Result<Collectors> {
        Collectors::new(modules, get_cli()?, Box::new(BpfEventsFactory::new()?))
    }

    #[test]
    fn register_collectors() -> Result<()> {
        let mut group = Modules::new()?;
        assert!(group
            .register(
                ModuleId::Skb,
                Box::new(DummyCollectorA::new()?),
                Box::<TestEvent>::default(),
            )
            .is_ok());
        assert!(group
            .register(
                ModuleId::Ovs,
                Box::new(DummyCollectorB::new()?),
                Box::<TestEvent>::default(),
            )
            .is_ok());
        Ok(())
    }

    #[test]
    fn register_uniqueness() -> Result<()> {
        let mut group = Modules::new()?;
        assert!(group
            .register(
                ModuleId::Skb,
                Box::new(DummyCollectorA::new()?),
                Box::<TestEvent>::default(),
            )
            .is_ok());
        assert!(group
            .register(
                ModuleId::Skb,
                Box::new(DummyCollectorA::new()?),
                Box::<TestEvent>::default(),
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn get_collectors() -> Result<()> {
        assert!(super::get_collectors(get_cli()?).is_ok());
        Ok(())
    }

    #[test]
    fn init_collectors() -> Result<()> {
        let mut group = Modules::new()?;
        let mut dummy_a = Box::new(DummyCollectorA::new()?);
        let mut dummy_b = Box::new(DummyCollectorB::new()?);

        group.register(
            ModuleId::Skb,
            Box::new(DummyCollectorA::new()?),
            Box::<TestEvent>::default(),
        )?;
        group.register(
            ModuleId::Ovs,
            Box::new(DummyCollectorB::new()?),
            Box::<TestEvent>::default(),
        )?;

        let mut collectors = new_collectors(group)?;
        let mut mgr = probe::ProbeManager::new()?;

        let config = get_config()?;
        assert!(dummy_a.init(&config, &mut mgr).is_ok());
        assert!(dummy_b.init(&config, &mut mgr).is_err());

        assert!(collectors.init().is_err());
        Ok(())
    }

    #[test]
    fn start_collectors() -> Result<()> {
        let mut group = Modules::new()?;
        let mut dummy_a = Box::new(DummyCollectorA::new()?);
        let mut dummy_b = Box::new(DummyCollectorB::new()?);

        group.register(
            ModuleId::Skb,
            Box::new(DummyCollectorA::new()?),
            Box::<TestEvent>::default(),
        )?;
        group.register(
            ModuleId::Ovs,
            Box::new(DummyCollectorB::new()?),
            Box::<TestEvent>::default(),
        )?;

        let mut collectors = new_collectors(group)?;

        assert!(dummy_a.start().is_ok());
        assert!(dummy_b.start().is_err());
        assert!(collectors.start().is_ok());
        Ok(())
    }

    #[test]
    fn parse_probe() -> Result<()> {
        let mut group = Modules::new()?;
        group.register(
            ModuleId::Skb,
            Box::new(DummyCollectorA::new()?),
            Box::<TestEvent>::default(),
        )?;
        group.register(
            ModuleId::Ovs,
            Box::new(DummyCollectorB::new()?),
            Box::<TestEvent>::default(),
        )?;

        let collectors = new_collectors(group)?;

        // Valid probes.
        assert!(collectors.parse_probe("consume_skb").is_ok());
        assert!(collectors.parse_probe("kprobe:kfree_skb_reason").is_ok());
        assert!(collectors.parse_probe("tp:skb:kfree_skb").is_ok());

        // Invalid probe: symbol does not exist.
        assert!(collectors.parse_probe("foobar").is_err());
        assert!(collectors.parse_probe("kprobe:foobar").is_err());
        assert!(collectors.parse_probe("tp:42:foobar").is_err());

        // Invalid probe: wrong TYPE.
        assert!(collectors.parse_probe("kprobe:skb:kfree_skb").is_err());
        assert!(collectors.parse_probe("skb:kfree_skb").is_err());
        assert!(collectors.parse_probe("foo:kfree_skb").is_err());

        // Invalid probe: empty parts.
        assert!(collectors.parse_probe("").is_err());
        assert!(collectors.parse_probe("kprobe:").is_err());
        assert!(collectors.parse_probe("tp:").is_err());
        assert!(collectors.parse_probe("tp:skb:").is_err());
        assert!(collectors.parse_probe(":kfree_skb_reason").is_err());

        Ok(())
    }
}
