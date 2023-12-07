#[cfg(not(test))]
use std::os::fd::{AsFd, AsRawFd};
use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::{self, BufWriter},
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use log::{debug, info, warn};
use nix::unistd::Uid;

use super::cli::Collect;
use crate::{
    cli::SubCommandRunner,
    core::filters::{meta::filter::FilterMeta, packets::filter::FilterPacketType},
    process::display::PrintSingle,
};

#[cfg(not(test))]
use crate::core::probe::kernel::{config::init_stack_map, kernel::KernelEventFactory};
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig, FullCli},
    core::{
        events::{bpf::BpfEventsFactory, EventFactory, EventResult},
        filters::{
            filters::{BpfFilter, Filter},
            packets::filter::FilterPacket,
        },
        inspect::check::collection_prerequisites,
        kernel::symbol::{matching_events_to_symbols, matching_functions_to_symbols},
        probe::*,
        signals::Running,
        tracking::{gc::TrackingGC, skb_tracking::init_tracking},
    },
    module::{ModuleId, Modules},
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
    /// Register command line arguments on the provided DynamicCommand object
    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()>;
    /// Check if the collector can run (eg. all prerequisites are matched). This
    /// is a separate step from init to allow skipping collectors when they are
    /// not explicitly selected by the user.
    ///
    /// The function should return an explanation when a collector can't run.
    fn can_run(&mut self, _: &CliConfig) -> Result<()> {
        Ok(())
    }
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
    fn init(&mut self, cli: &CliConfig, probes: &mut ProbeBuilderManager) -> Result<()>;
    /// Start the collector.
    fn start(&mut self) -> Result<()> {
        Ok(())
    }
    /// Stop the collector.
    fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Main collectors object and API.
pub(crate) struct Collectors {
    modules: Modules,
    probes: ProbeManager,
    factory: BpfEventsFactory,
    known_kernel_types: HashSet<String>,
    run: Running,
    tracking_gc: Option<TrackingGC>,
    // Keep a reference on the tracking configuration map.
    tracking_config_map: Option<libbpf_rs::MapHandle>,
    loaded: Vec<ModuleId>,
}

impl Collectors {
    fn new(modules: Modules) -> Result<Self> {
        let factory = BpfEventsFactory::new()?;
        let probes = ProbeManager::new()?;

        Ok(Collectors {
            modules,
            probes,
            factory,
            known_kernel_types: HashSet::new(),
            run: Running::new(),
            tracking_gc: None,
            tracking_config_map: None,
            loaded: Vec::new(),
        })
    }

    // Register the dynamic commands with the cli and parse collector-specific arguments
    fn register_cli(&mut self, mut cli: FullCli) -> Result<CliConfig> {
        // Register all collectors' command line arguments. Cli registration
        // errors are fatal.
        let cmd = cli.get_subcommand_mut()?.dynamic_mut().unwrap();
        self.modules
            .collectors()
            .iter()
            .try_for_each(|(_, c)| c.register_cli(cmd))?;

        // Now we can parse all parameters.
        Ok(cli.run()?)
    }

    /// Setup user defined input filter.
    fn setup_filters(probes: &mut ProbeBuilderManager, collect: &Collect) -> Result<()> {
        if let Some(f) = &collect.args()?.packet_filter {
            // L2 filter MUST always succeed. Any failure means we need to bail.
            let fb = FilterPacket::from_string_opt(f.to_string(), FilterPacketType::L2)?;

            probes.register_filter(Filter::Packet(
                FilterPacketType::L2,
                BpfFilter(fb.to_bytes()?),
            ))?;

            let mut loaded_info = "L2";
            // L3 filter is non mandatory.
            let fb = if f.contains("ether[") {
                debug!("Skipping L3 filter generation (ether[n:m] not allowed)");
                FilterPacket::reject_filter()
            } else {
                match FilterPacket::from_string_opt(f.to_string(), FilterPacketType::L3) {
                    Err(e) => {
                        debug!("Skipping L3 filter generation ({e}).");
                        FilterPacket::reject_filter()
                    }
                    Ok(f) => {
                        loaded_info = "L2+L3";
                        f
                    }
                }
            };

            probes.register_filter(Filter::Packet(
                FilterPacketType::L3,
                BpfFilter(fb.to_bytes()?),
            ))?;

            info!("{} packet filter(s) loaded", loaded_info);
        }

        if let Some(f) = &collect.args()?.meta_filter {
            let fb =
                FilterMeta::from_string(f.to_string()).map_err(|e| anyhow!("meta filter: {e}"))?;
            probes.register_filter(Filter::Meta(fb))?;
        }

        Ok(())
    }

    /// Initialize all collectors by calling their `init()` function.
    pub(crate) fn init(&mut self, cli: &CliConfig) -> Result<()> {
        self.run.register_term_signals()?;

        let collect = cli
            .subcommand
            .as_any()
            .downcast_ref::<Collect>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?;

        if collect.args()?.stack {
            self.probes
                .builder_mut()?
                .set_probe_opt(probe::ProbeOption::StackTrace)?;
        }

        // --allow-system-changes requires root.
        if collect.args()?.allow_system_changes && !Uid::effective().is_root() {
            bail!("Retis needs to be run as root when --allow-system-changes is used");
        }

        // Try initializing all collectors.
        for name in &collect.args()?.collectors {
            let id = ModuleId::from_str(name)?;
            let c = self
                .modules
                .get_collector(&id)
                .ok_or_else(|| anyhow!("unknown collector {}", name))?;

            // Check if the collector can run (prerequisites are met).
            if let Err(e) = c.can_run(cli) {
                // Do not issue an error if the list of collectors was set by
                // default, aka. auto-detect mode.
                if collect.default_collectors_list {
                    debug!("Can't run collector {id}: {e}");
                    continue;
                } else {
                    bail!("Can't run collector {id}: {e}");
                }
            }

            if let Err(e) = c.init(cli, self.probes.builder_mut()?) {
                bail!("Could not initialize the {} collector: {}", id, e);
            }

            self.loaded.push(id);

            // If the collector provides known kernel types, meaning we have a
            // dynamic collector, retrieve and store them for later processing.
            if let Some(kt) = c.known_kernel_types() {
                kt.into_iter().for_each(|x| {
                    self.known_kernel_types.insert(x.to_string());
                });
            }
        }

        //  If auto-mode is used, print the list of module that were started.
        if collect.default_collectors_list {
            info!(
                "Collector(s) started: {}",
                self.loaded
                    .iter()
                    .map(|id| id.to_str())
                    .collect::<Vec<&str>>()
                    .join(", ")
            );
        }

        // Initialize tracking & filters.
        if !cfg!(test) && self.known_kernel_types.contains("struct sk_buff *") {
            let (gc, map) = init_tracking(self.probes.builder_mut()?)?;
            self.tracking_gc = Some(gc);
            self.tracking_config_map = Some(map);
        }
        Self::setup_filters(self.probes.builder_mut()?, collect)?;

        // Setup user defined probes.
        collect
            .args()?
            .probes
            .iter()
            .try_for_each(|p| -> Result<()> {
                self.parse_probe(p)?
                    .drain(..)
                    .try_for_each(|p| self.probes.builder_mut()?.register_probe(p))?;
                Ok(())
            })?;

        Ok(())
    }

    /// Start the event retrieval for all collectors by calling
    /// their `start()` function.
    pub(crate) fn start(&mut self) -> Result<()> {
        // Create factories.
        #[cfg_attr(test, allow(unused_mut))]
        let mut section_factories = self.modules.section_factories()?;

        #[cfg(not(test))]
        {
            let sm = init_stack_map()?;
            self.probes
                .builder_mut()?
                .reuse_map("stack_map", sm.as_fd().as_raw_fd())?;
            self.probes
                .builder_mut()?
                .reuse_map("events_map", self.factory.map_fd())?;
            match section_factories.get_mut(&ModuleId::Kernel) {
                Some(kernel_factory) => {
                    kernel_factory
                        .as_any_mut()
                        .downcast_mut::<KernelEventFactory>()
                        .ok_or_else(|| anyhow!("Failed to downcast KernelEventFactory"))?
                        .stack_map = Some(sm)
                }

                None => bail!("Can't get kernel section factory"),
            }
        }

        if let Some(gc) = &mut self.tracking_gc {
            gc.start(self.run.clone())?;
        }

        // Start factory
        self.factory.start(section_factories)?;

        // Attach probes and start collectors. We're using an open coded take &
        // replace combination. We could use a Cell<> instead but that would
        // complicate the use of self.probes (additional .get() calls) while
        // behaving the same.
        let probes = std::mem::take(&mut self.probes);
        let _ = std::mem::replace(&mut self.probes, probes.into_runtime()?);

        for id in &self.loaded {
            let c = self
                .modules
                .get_collector(id)
                .ok_or_else(|| anyhow!("unknown collector {}", id.to_str()))?;

            debug!("Starting collector {id}");
            if c.start().is_err() {
                warn!("Could not start collector {id}");
            }
        }

        Ok(())
    }

    /// Stop the event retrieval for all collectors in the group by calling
    /// their `stop()` function. All the collectors are in charge to clean-up
    /// their temporary side effects and exit gracefully.
    fn stop(&mut self) -> Result<()> {
        self.probes.runtime_mut()?.detach()?;
        self.probes.runtime_mut()?.report_counters()?;

        for id in &self.loaded {
            let c = self
                .modules
                .get_collector(id)
                .ok_or_else(|| anyhow!("unknown collector {}", id.to_str()))?;

            debug!("Stopping collector {id}");
            if c.stop().is_err() {
                warn!("Could not stop collector {id}");
            }
        }

        // We're not actually stopping but just joining. The actual
        // termination got performed implicitly by the signal handler.
        // The print-out is just for consistency.
        debug!("Stopping tracking gc");
        if let Some(gc) = &mut self.tracking_gc {
            gc.join()?;
        }

        debug!("Stopping events");
        self.factory.stop()?;

        Ok(())
    }

    /// Starts the processing loop and block until we get a single SIGINT
    /// (e.g. ctrl+c), then return after properly cleaning up. This is the main
    /// collector cmd loop.
    pub(crate) fn process(&mut self, cli: &CliConfig) -> Result<()> {
        let collect = cli
            .subcommand
            .as_any()
            .downcast_ref::<Collect>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?
            .args()?;

        let mut printers = Vec::new();

        // Write events to stdout if we don't write to a file (--out) or if
        // explicitly asked to (--print).
        if collect.out.is_none() || collect.print {
            printers.push(PrintSingle::text(Box::new(io::stdout()), collect.format));
        }

        // Write the events to a file if asked to.
        if let Some(out) = collect.out.as_ref() {
            printers.push(PrintSingle::json(Box::new(BufWriter::new(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(out)
                    .or_else(|_| bail!("Could not create or open '{}'", out.display()))?,
            ))));
        }

        if let Some(cmd) = collect.cmd.to_owned() {
            let run = self.run.clone();
            std::thread::spawn(move || {
                match Command::new("sh")
                    .arg("-c")
                    .arg(&cmd)
                    .stderr(Stdio::null())
                    .stdout(Stdio::null())
                    .status()
                {
                    Err(e) => warn!("Failed to execute command {e}"),
                    Ok(status) => {
                        info!("Command returned ({status}), terminating ...");
                    }
                }

                run.terminate();
            });
        }

        use EventResult::*;
        while self.run.running() {
            match self.factory.next_event(Some(Duration::from_secs(1)))? {
                Event(event) => printers
                    .iter_mut()
                    .try_for_each(|p| p.process_one(&event))?,
                Eof => break,
                Timeout => continue,
            }
        }

        printers.iter_mut().try_for_each(|p| p.flush())?;
        self.stop()
    }

    /// Parse a user defined probe (through cli parameters) and extract its type and
    /// target.
    fn parse_probe(&self, probe: &str) -> Result<Vec<Probe>> {
        let (type_str, target) = match probe.split_once(':') {
            Some((type_str, target)) => (type_str, target),
            None => ("kprobe", probe),
        };

        // Convert the target to a list of matching ones for probe types
        // supporting it.
        let mut symbols = match type_str {
            "kprobe" | "kretprobe" => matching_functions_to_symbols(target)?,
            "tp" => matching_events_to_symbols(target)?,
            x => bail!("Invalid TYPE {}. See the help.", x),
        };

        let mut probes = Vec::new();
        for symbol in symbols.drain(..) {
            // Check if the probe would be used by a collector to retrieve data.
            let mut valid = false;
            for r#type in self.known_kernel_types.iter() {
                if symbol.parameter_offset(r#type)?.is_some() {
                    valid = true;
                    break;
                }
            }
            // Skip probes which won't generate events from the collectors.
            if !valid {
                info!(
                    "No probe was attached to {symbol} as no collector could retrieve data from it"
                );
                continue;
            }

            probes.push(match type_str {
                "kprobe" => Probe::kprobe(symbol)?,
                "kretprobe" => Probe::kretprobe(symbol)?,
                "tp" => Probe::raw_tracepoint(symbol)?,
                x => bail!("Invalid TYPE {}. See the help.", x),
            })
        }

        Ok(probes)
    }
}

pub(crate) struct CollectRunner {}

impl SubCommandRunner for CollectRunner {
    fn check_prerequisites(&self) -> Result<()> {
        collection_prerequisites()
    }

    fn run(&mut self, cli: FullCli, modules: Modules) -> Result<()> {
        // Initialize collectors.
        let mut collectors = Collectors::new(modules)?;
        let cli = collectors.register_cli(cli)?;
        collectors.init(&cli)?;
        collectors.start()?;
        // Starts a loop.
        collectors.process(&cli)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{
            events::{bpf::BpfRawSection, *},
            probe::ProbeBuilderManager,
        },
        event_section, event_section_factory,
        module::Module,
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
        fn init(&mut self, _: &CliConfig, _: &mut ProbeBuilderManager) -> Result<()> {
            Ok(())
        }
        fn start(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl Module for DummyCollectorA {
        fn collector(&mut self) -> &mut dyn Collector {
            self
        }
        fn section_factory(&self) -> Result<Box<dyn EventSectionFactory>> {
            Ok(Box::new(TestEvent {}))
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
        fn init(&mut self, _: &CliConfig, _: &mut ProbeBuilderManager) -> Result<()> {
            bail!("Could not initialize")
        }
        fn start(&mut self) -> Result<()> {
            bail!("Could not start");
        }
    }

    impl Module for DummyCollectorB {
        fn collector(&mut self) -> &mut dyn Collector {
            self
        }
        fn section_factory(&self) -> Result<Box<dyn EventSectionFactory>> {
            Ok(Box::new(TestEvent {}))
        }
    }

    #[event_section]
    #[event_section_factory(Self)]
    struct TestEvent {}

    impl EventFmt for TestEvent {
        fn event_fmt(&self, f: &mut std::fmt::Formatter, _: DisplayFormat) -> std::fmt::Result {
            write!(f, "test event section")
        }
    }

    impl RawEventSectionFactory for TestEvent {
        fn from_raw(&mut self, _: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
            Ok(Box::new(TestEvent::default()))
        }
    }

    fn get_cli() -> Result<FullCli> {
        Ok(crate::cli::get_cli()?.build_from(vec!["retis", "collect"])?)
    }

    #[test]
    fn register_collectors() -> Result<()> {
        let mut group = Modules::new()?;
        assert!(group
            .register(ModuleId::Skb, Box::new(DummyCollectorA::new()?),)
            .is_ok());
        assert!(group
            .register(ModuleId::Ovs, Box::new(DummyCollectorB::new()?),)
            .is_ok());
        Ok(())
    }

    #[test]
    fn register_uniqueness() -> Result<()> {
        let mut group = Modules::new()?;
        assert!(group
            .register(ModuleId::Skb, Box::new(DummyCollectorA::new()?),)
            .is_ok());
        assert!(group
            .register(ModuleId::Skb, Box::new(DummyCollectorA::new()?),)
            .is_err());
        Ok(())
    }

    #[test]
    fn init_collectors() -> Result<()> {
        let mut group = Modules::new()?;
        let mut dummy_a = Box::new(DummyCollectorA::new()?);
        let mut dummy_b = Box::new(DummyCollectorB::new()?);

        group.register(ModuleId::Skb, Box::new(DummyCollectorA::new()?))?;
        group.register(ModuleId::Ovs, Box::new(DummyCollectorB::new()?))?;

        let mut collectors = Collectors::new(group)?;
        let mut mgr = ProbeBuilderManager::new()?;
        let mut config = collectors.register_cli(get_cli()?)?;

        assert!(dummy_a.init(&config, &mut mgr).is_ok());
        assert!(dummy_b.init(&config, &mut mgr).is_err());

        assert!(collectors.init(&mut config).is_err());
        Ok(())
    }

    #[test]
    fn start_collectors() -> Result<()> {
        let mut group = Modules::new()?;
        let mut dummy_a = Box::new(DummyCollectorA::new()?);
        let mut dummy_b = Box::new(DummyCollectorB::new()?);

        group.register(ModuleId::Skb, Box::new(DummyCollectorA::new()?))?;
        group.register(ModuleId::Ovs, Box::new(DummyCollectorB::new()?))?;

        let mut collectors = Collectors::new(group)?;

        assert!(dummy_a.start().is_ok());
        assert!(dummy_b.start().is_err());
        assert!(collectors.start().is_ok());
        Ok(())
    }

    #[test]
    fn parse_probe() -> Result<()> {
        let mut group = Modules::new()?;
        group.register(ModuleId::Skb, Box::new(DummyCollectorA::new()?))?;

        let mut collectors = Collectors::new(group)?;
        let mut config = collectors.register_cli(get_cli()?)?;
        collectors.init(&mut config)?;

        // Valid probes.
        assert!(collectors.parse_probe("consume_skb").is_ok());
        assert!(collectors.parse_probe("kprobe:kfree_skb_reason").is_ok());
        assert!(collectors.parse_probe("tp:skb:kfree_skb").is_ok());
        assert!(collectors.parse_probe("tcp_v6_*").is_ok());
        assert!(collectors.parse_probe("kprobe:tcp_v6_*").is_ok());
        assert!(collectors.parse_probe("kprobe:tcp_v6_*")?.len() > 0);
        assert!(collectors.parse_probe("kretprobe:tcp_*").is_ok());
        assert!(collectors.parse_probe("tp:skb:kfree_*").is_ok());
        assert!(collectors.parse_probe("tp:*skb*").is_ok());

        // Invalid probe: symbol does not exist.
        assert!(collectors.parse_probe("foobar").is_err());
        assert!(collectors.parse_probe("kprobe:foobar").is_err());
        assert!(collectors.parse_probe("tp:42:foobar").is_err());
        assert!(collectors.parse_probe("tp:kfree_*").is_err());
        assert!(collectors.parse_probe("*foo*").is_err());

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
