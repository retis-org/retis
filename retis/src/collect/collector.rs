#[cfg(not(test))]
use std::os::fd::{AsFd, AsRawFd};
use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::{self, BufWriter},
    process::{Command, Stdio},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use log::{debug, info, warn};
use nix::{errno::Errno, mount::*, unistd::Uid};

use super::cli::Collect;
use crate::{
    bindings::packet_filter_uapi,
    cli::{dynamic::DynamicCommand, CliConfig, CliDisplayFormat, FullCli, SubCommandRunner},
    core::{
        events::{BpfEventsFactory, EventResult, RetisEventsFactory},
        filters::{
            filters::{BpfFilter, Filter},
            meta::filter::FilterMeta,
            packets::filter::FilterPacket,
        },
        inspect::check::collection_prerequisites,
        kernel::Symbol,
        probe::{
            kernel::{probe_stack::ProbeStack, utils::probe_from_cli},
            *,
        },
        tracking::{gc::TrackingGC, skb_tracking::init_tracking},
    },
    events::*,
    helpers::{signals::Running, time::*},
    module::{ModuleId, Modules},
    process::display::*,
};

#[cfg(not(test))]
use crate::core::{
    events::FactoryId,
    probe::kernel::{config::init_stack_map, kernel::KernelEventFactory},
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
    fn init(
        &mut self,
        cli: &CliConfig,
        probes: &mut ProbeBuilderManager,
        events_factory: Arc<RetisEventsFactory>,
    ) -> Result<()>;
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
    // Retis events factory.
    events_factory: Arc<RetisEventsFactory>,
    // Did we mount debugfs ourselves?
    mounted_debugfs: bool,
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
            events_factory: Arc::new(RetisEventsFactory::default()),
            mounted_debugfs: false,
        })
    }

    /// Setup user defined input filter.
    fn setup_filters(probes: &mut ProbeBuilderManager, collect: &Collect) -> Result<()> {
        if let Some(f) = &collect.args()?.packet_filter {
            // L2 filter MUST always succeed. Any failure means we need to bail.
            let fb = FilterPacket::from_string_opt(f.to_string(), packet_filter_uapi::FILTER_L2)?;

            probes.register_filter(Filter::Packet(
                packet_filter_uapi::FILTER_L2,
                BpfFilter(fb.to_bytes()?),
            ))?;

            let mut loaded_info = "L2";
            // L3 filter is non mandatory.
            let fb = if f.contains("ether[") {
                debug!("Skipping L3 filter generation (ether[n:m] not allowed)");
                FilterPacket::reject_filter()
            } else {
                match FilterPacket::from_string_opt(f.to_string(), packet_filter_uapi::FILTER_L3) {
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
                packet_filter_uapi::FILTER_L3,
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

    /// Check prerequisites and cli arguments to ensure we can run.
    fn check(&mut self, cli: &CliConfig) -> Result<()> {
        let collect = cli
            .subcommand
            .as_any()
            .downcast_ref::<Collect>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?
            .args()?;

        if collect.probe_stack && collect.packet_filter.is_none() && collect.meta_filter.is_none() {
            bail!("Probe-stack mode requires filtering (--filter-packet and/or --filter-meta)");
        }

        // --allow-system-changes requires root.
        if collect.allow_system_changes && !Uid::effective().is_root() {
            bail!("Retis needs to be run as root when --allow-system-changes is used");
        }

        // Mount debugfs if not already mounted (and if we can). This is
        // especially useful when running Retis in namespaces and containers.
        if collect.allow_system_changes {
            const DEBUGFS_TARGET: &str = "/sys/kernel/debug";

            let err = mount(
                None::<&std::path::Path>,
                std::path::Path::new(DEBUGFS_TARGET),
                Some("debugfs"),
                MsFlags::empty(),
                None::<&str>,
            );

            match err {
                Ok(_) => {
                    debug!("Mounted debugfs to {DEBUGFS_TARGET}");
                    self.mounted_debugfs = true;
                }
                Err(errno) => match errno {
                    Errno::EBUSY => debug!("Debugfs is already mounted to {DEBUGFS_TARGET}"),
                    _ => warn!("Could not mount debugfs to {DEBUGFS_TARGET}: {errno}"),
                },
            }
        }

        // Check prerequisites.
        collection_prerequisites()
    }

    /// Initialize all collectors by calling their `init()` function.
    fn init(&mut self, cli: &CliConfig) -> Result<()> {
        self.run.register_term_signals()?;

        let collect = cli
            .subcommand
            .as_any()
            .downcast_ref::<Collect>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?;

        // Check if we need to report stack traces in the events.
        if collect.args()?.stack || collect.args()?.probe_stack {
            self.probes
                .builder_mut()?
                .set_probe_opt(probe::ProbeOption::StackTrace)?;
        }

        // Generate an initial event with the startup section.
        self.events_factory.add_event(|event| {
            event.insert_section(
                SectionId::Startup,
                Box::new(StartupEvent {
                    retis_version: option_env!("RELEASE_VERSION")
                        .unwrap_or("unspec")
                        .to_string(),
                    clock_monotonic_offset: monotonic_clock_offset()?,
                }),
            )
        })?;

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

            if let Err(e) = c.init(
                cli,
                self.probes.builder_mut()?,
                Arc::clone(&self.events_factory),
            ) {
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

        // If probe_stack is on and user hasn't provided a starting point, use
        // skb:consume_skb & skb:kfree_skb.
        if collect.args()?.probe_stack && collect.args()?.probes.is_empty() {
            self.probes
                .builder_mut()?
                .register_probe(Probe::raw_tracepoint(Symbol::from_name(
                    "skb:consume_skb",
                )?)?)?;
            self.probes
                .builder_mut()?
                .register_probe(Probe::raw_tracepoint(Symbol::from_name("skb:kfree_skb")?)?)?;
        }

        // Setup user defined probes.
        let filter = |symbol: &Symbol| {
            // Skip probes not being compatible with the loaded modules.
            let ok = self.known_kernel_types.iter().any(|t| {
                symbol
                    .parameter_offset(t)
                    .is_ok_and(|offset| offset.is_some())
            });
            if !ok {
                info!(
                    "No probe was attached to {} as no collector could retrieve data from it",
                    symbol
                );
            }
            ok
        };
        collect
            .args()?
            .probes
            .iter()
            .try_for_each(|p| -> Result<()> {
                probe_from_cli(p, filter)?
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
            self.probes
                .builder_mut()?
                .reuse_map("log_map", self.factory.log_map_fd())?;
            match section_factories.get_mut(&FactoryId::Kernel) {
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

        // If we mounted debugfs, unmount it.
        if self.mounted_debugfs {
            debug!("Unmounting debugfs");
            umount("/sys/kernel/debug")?;
        }

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
            let format = DisplayFormat::new()
                .multiline(collect.format == CliDisplayFormat::MultiLine)
                .time_format(if collect.utc {
                    TimeFormat::UtcDate
                } else {
                    TimeFormat::MonotonicTimestamp
                })
                .monotonic_offset(monotonic_clock_offset()?);

            printers.push(PrintEvent::new(
                Box::new(io::stdout()),
                PrintEventFormat::Text(format),
            ));
        }

        // Write the events to a file if asked to.
        if let Some(out) = collect.out.as_ref() {
            printers.push(PrintEvent::new(
                Box::new(BufWriter::new(
                    OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(out)
                        .or_else(|_| bail!("Could not create or open '{}'", out.display()))?,
                )),
                PrintEventFormat::Json,
            ));
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

        let mut probe_stack = ProbeStack::new(
            collect.stack,
            self.probes.runtime_mut()?.attached_probes(),
            self.known_kernel_types.clone(),
        );

        use EventResult::*;
        while self.run.running() {
            // First always try to dequeue all Retis events. This is not a
            // blocking call.
            while let Some(event) = self.events_factory.next_event() {
                printers
                    .iter_mut()
                    .try_for_each(|p| p.process_one(&event))?;
            }

            // Then get raw events, if any.
            match self.factory.next_event(Some(Duration::from_secs(1)))? {
                Event(mut event) => {
                    if collect.probe_stack {
                        probe_stack.process_event(self.probes.runtime_mut()?, &mut event)?;
                    }

                    printers
                        .iter_mut()
                        .try_for_each(|p| p.process_one(&event))?;
                }
                Timeout => continue,
            }
        }

        printers.iter_mut().try_for_each(|p| p.flush())?;
        self.stop()
    }
}

pub(crate) struct CollectRunner {}

impl SubCommandRunner for CollectRunner {
    fn run(&mut self, cli: FullCli, modules: Modules) -> Result<()> {
        // Collector arguments are arealdy registered when build FullCli
        let cli = cli.run()?;

        // Initialize & start collectors.
        let mut collectors = Collectors::new(modules)?;
        collectors.check(&cli)?;
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
        core::{events::bpf::*, probe::ProbeBuilderManager},
        event_section_factory,
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
            cli.register_module_noargs(SectionId::Skb)
        }
        fn init(
            &mut self,
            _: &CliConfig,
            _: &mut ProbeBuilderManager,
            factory: Arc<RetisEventsFactory>,
        ) -> Result<()> {
            factory.add_event(|_| Ok(()))?;
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
        fn section_factory(&self) -> Result<Option<Box<dyn EventSectionFactory>>> {
            Ok(Some(Box::new(TestEventFactory::default())))
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
            cli.register_module_noargs(SectionId::Ovs)
        }
        fn init(
            &mut self,
            _: &CliConfig,
            _: &mut ProbeBuilderManager,
            _: Arc<RetisEventsFactory>,
        ) -> Result<()> {
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
        fn section_factory(&self) -> Result<Option<Box<dyn EventSectionFactory>>> {
            Ok(Some(Box::new(TestEventFactory::default())))
        }
    }

    #[event_section_factory(FactoryId::Common)]
    #[derive(Default)]
    struct TestEventFactory {}

    impl RawEventSectionFactory for TestEventFactory {
        fn create(&mut self, _: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
            Ok(Box::<TestEvent>::default())
        }
    }

    fn get_cli(modules: &str) -> Result<FullCli> {
        Ok(crate::cli::get_cli()?.build_from(vec!["retis", "collect", "-c", modules])?)
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
        let factory = Arc::new(RetisEventsFactory::default());
        let config = get_cli("skb,ovs")?.run()?;

        assert!(dummy_a
            .init(&config, &mut mgr, Arc::clone(&factory))
            .is_ok());
        assert!(dummy_b
            .init(&config, &mut mgr, Arc::clone(&factory))
            .is_err());

        assert!(collectors.init(&config).is_err());
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
}
