use std::{
    collections::{HashMap, HashSet},
    sync::mpsc,
    thread,
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use log::{error, info, warn};
use signal_hook::{consts::SIGINT, iterator::Signals};

use super::{
    cli::Collect,
    output::{get_processors, JsonFormat},
};
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    core::{
        events::bpf::BpfEvents,
        kernel::Symbol,
        probe::{self, Probe},
    },
    module::{ovs::OvsCollector, skb::SkbCollector, skb_tracking::SkbTrackingCollector},
};

/// Generic trait representing a collector. All collectors are required to
/// implement this, as they'll be manipulated through this trait.
pub(crate) trait Collector {
    /// Allocate and return a new instance of the collector, using only default
    /// values for its internal fields.
    fn new() -> Result<Self>
    where
        Self: Sized;
    /// Return the name of the collector. It *has* to be unique among all the
    /// collectors.
    fn name(&self) -> &'static str;
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
    fn init(
        &mut self,
        cli: &CliConfig,
        probes: &mut probe::ProbeManager,
        events: &mut BpfEvents,
    ) -> Result<()>;
    /// Start the group of events (non-probes).
    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Group of collectors. Used to handle a set of collectors and to perform
/// group actions.
pub(crate) struct Group {
    list: HashMap<String, Box<dyn Collector>>,
    probes: probe::ProbeManager,
    events: BpfEvents,
    known_kernel_types: HashSet<String>,
}

impl Group {
    fn new() -> Result<Group> {
        let mut events = BpfEvents::new()?;
        let probes = probe::ProbeManager::new(&mut events)?;
        Ok(Group {
            list: HashMap::new(),
            probes,
            events,
            known_kernel_types: HashSet::new(),
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
    fn register(&mut self, collector: Box<dyn Collector>) -> Result<&mut Self> {
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

    /// Initialize all collectors by calling their `init()` function.
    pub(crate) fn init(&mut self, cli: &CliConfig) -> Result<()> {
        let collect = cli
            .subcommand
            .as_any()
            .downcast_ref::<Collect>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?;

        probe::common::set_ebpf_debug(collect.args()?.ebpf_debug)?;
        if collect.args()?.stack {
            self.probes.add_probe_opt(probe::ProbeOption::StackTrace);
        }

        // Try initializing all collectors in the group.
        for name in &collect.args()?.collectors {
            let c = self
                .list
                .get_mut(name)
                .ok_or_else(|| anyhow!("unknown collector: {}", &name))?;

            if let Err(e) = c.init(cli, &mut self.probes, &mut self.events) {
                bail!("Could not initialize the {} collector: {}", c.name(), e);
            }

            // If the collector provides known kernel types, meaning we have a
            // dynamic collector, retrieve and store them for later processing.
            if let Some(kt) = c.known_kernel_types() {
                kt.into_iter().for_each(|x| {
                    self.known_kernel_types.insert(x.to_string());
                });
            }
        }

        // Setup user defined probes.
        for probe in collect.args()?.probes.iter() {
            self.probes.add_probe(self.parse_probe(probe)?)?;
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

    /// Start the event retrieval for all collectors in the group by calling
    /// their `start()` function. Collectors failing to start the event
    /// retrieval will be kept in the group.
    pub(crate) fn start(&mut self, _: &CliConfig) -> Result<()> {
        self.events.start_polling()?;
        self.probes.attach()?;

        for (_, c) in self.list.iter_mut() {
            if c.start().is_err() {
                warn!("Could not start '{}'", c.name());
            }
        }

        Ok(())
    }

    /// Starts the processing loop and block until we get a single SIGINT
    /// (e.g. ctrl+c), then return after properly cleaning up. This is the main
    /// collector cmd loop.
    pub(crate) fn process(&self, cli: &CliConfig) -> Result<()> {
        let collect = cli
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
            match self.events.poll(Some(Duration::from_secs(1)))? {
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
pub(crate) fn get_collectors() -> Result<Group> {
    let mut group = Group::new()?;

    // Register all collectors here.
    group
        .register(Box::new(SkbTrackingCollector::new()?))?
        .register(Box::new(SkbCollector::new()?))?
        .register(Box::new(OvsCollector::new()?))?;

    Ok(group)
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
        fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
            Some(vec!["struct sk_buff *", "struct net_device *"])
        }
        fn register_cli(&self, _: &mut DynamicCommand) -> Result<()> {
            Ok(())
        }
        fn init(
            &mut self,
            _: &CliConfig,
            _: &mut probe::ProbeManager,
            _: &mut BpfEvents,
        ) -> Result<()> {
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
        fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
            None
        }
        fn register_cli(&self, _: &mut DynamicCommand) -> Result<()> {
            Ok(())
        }
        fn init(
            &mut self,
            _: &CliConfig,
            _: &mut probe::ProbeManager,
            _: &mut BpfEvents,
        ) -> Result<()> {
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
    fn get_collectors() {
        assert!(super::get_collectors().is_ok());
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
        let mut mgr = probe::ProbeManager::new(&mut events)?;

        assert!(dummy_a.init(&config, &mut mgr, &mut events).is_ok());
        assert!(dummy_b.init(&config, &mut mgr, &mut events).is_err());
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

    #[test]
    fn parse_probe() -> Result<()> {
        let mut group = Group::new()?;
        group.register(Box::new(DummyCollectorA::new()?))?;
        group.register(Box::new(DummyCollectorB::new()?))?;

        // Valid probes.
        assert!(group.parse_probe("consume_skb").is_ok());
        assert!(group.parse_probe("kprobe:kfree_skb_reason").is_ok());
        assert!(group.parse_probe("tp:skb:kfree_skb").is_ok());

        // Invalid probe: symbol does not exist.
        assert!(group.parse_probe("foobar").is_err());
        assert!(group.parse_probe("kprobe:foobar").is_err());
        assert!(group.parse_probe("tp:42:foobar").is_err());

        // Invalid probe: wrong TYPE.
        assert!(group.parse_probe("kprobe:skb:kfree_skb").is_err());
        assert!(group.parse_probe("skb:kfree_skb").is_err());
        assert!(group.parse_probe("foo:kfree_skb").is_err());

        // Invalid probe: empty parts.
        assert!(group.parse_probe("").is_err());
        assert!(group.parse_probe("kprobe:").is_err());
        assert!(group.parse_probe("tp:").is_err());
        assert!(group.parse_probe("tp:skb:").is_err());
        assert!(group.parse_probe(":kfree_skb_reason").is_err());

        Ok(())
    }
}
