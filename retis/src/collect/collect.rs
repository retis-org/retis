#[cfg(not(test))]
use std::os::fd::{AsFd, AsRawFd};
use std::{
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    io::{self, BufWriter},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use log::{debug, info, warn};
use nix::{errno::Errno, mount::*, unistd::Uid};

use super::{
    cli::Collect,
    collector::{
        ct::CtCollector, nft::NftCollector, ovs::OvsCollector, skb::SkbCollector,
        skb_drop::SkbDropCollector, skb_tracking::SkbTrackingCollector,
    },
};
use crate::{
    bindings::packet_filter_uapi,
    cli::CliDisplayFormat,
    collect::collector::{section_factories, skb::SkbEventFactory},
    core::{
        events::{BpfEventsFactory, EventResult, FactoryId, RetisEventsFactory},
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
    process::display::*,
};

#[cfg(not(test))]
use crate::core::probe::kernel::{config::init_stack_map, kernel::KernelEventFactory};

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
    /// Check if the collector can run (eg. all prerequisites are matched). This
    /// is a separate step from init to allow skipping collectors when they are
    /// not explicitly selected by the user.
    ///
    /// The function should return an explanation when a collector can't run.
    fn can_run(&mut self, _: &Collect) -> Result<()> {
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
        collect: &Collect,
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
    collectors: HashMap<String, Box<dyn Collector>>,
    probes: ProbeManager,
    factory: BpfEventsFactory,
    known_kernel_types: HashSet<String>,
    run: Running,
    tracking_gc: Option<TrackingGC>,
    // Keep a reference on the tracking configuration map.
    tracking_config_map: Option<libbpf_rs::MapHandle>,
    // Retis events factory.
    events_factory: Arc<RetisEventsFactory>,
    // Did we mount debugfs ourselves?
    mounted_debugfs: bool,
}

impl Collectors {
    pub(super) fn new() -> Result<Self> {
        let factory = BpfEventsFactory::new()?;
        let probes = ProbeManager::new()?;

        Ok(Collectors {
            collectors: HashMap::new(),
            probes,
            factory,
            known_kernel_types: HashSet::new(),
            run: Running::new(),
            tracking_gc: None,
            tracking_config_map: None,
            events_factory: Arc::new(RetisEventsFactory::default()),
            mounted_debugfs: false,
        })
    }

    /// Setup user defined input filter.
    fn setup_filters(probes: &mut ProbeBuilderManager, collect: &Collect) -> Result<()> {
        if let Some(f) = &collect.packet_filter {
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

        if let Some(f) = &collect.meta_filter {
            let fb =
                FilterMeta::from_string(f.to_string()).map_err(|e| anyhow!("meta filter: {e}"))?;
            probes.register_filter(Filter::Meta(fb))?;
        }

        Ok(())
    }

    /// Check prerequisites and cli arguments to ensure we can run.
    pub(super) fn check(&mut self, collect: &Collect) -> Result<()> {
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
    pub(super) fn init(&mut self, collect: &Collect) -> Result<()> {
        self.run.register_term_signals()?;

        // Check if we need to report stack traces in the events.
        if collect.stack || collect.probe_stack {
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

        let (auto_mode, collectors) = match &collect.collectors {
            Some(collectors) => (
                false,
                collectors.iter().map(|c| c.as_ref()).collect::<Vec<&str>>(),
            ),
            None => (
                true,
                vec!["skb-tracking", "skb", "skb-drop", "ovs", "nft", "ct"],
            ),
        };

        // Try initializing all collectors.
        for name in collectors {
            let mut c: Box<dyn Collector> = match name {
                "skb-tracking" => Box::new(SkbTrackingCollector::new()?),
                "skb" => Box::new(SkbCollector::new()?),
                "skb-drop" => Box::new(SkbDropCollector::new()?),
                "ovs" => Box::new(OvsCollector::new()?),
                "nft" => Box::new(NftCollector::new()?),
                "ct" => Box::new(CtCollector::new()?),
                _ => bail!("Unknown collector {name}"),
            };

            // Check if the collector can run (prerequisites are met).
            if let Err(e) = c.can_run(collect) {
                // Do not issue an error if the list of collectors was set by
                // default, aka. auto-detect mode.
                if auto_mode {
                    debug!("Cannot run collector {name}: {e}");
                    continue;
                } else {
                    bail!("Cannot run collector {name}: {e}");
                }
            }

            if let Err(e) = c.init(
                collect,
                self.probes.builder_mut()?,
                Arc::clone(&self.events_factory),
            ) {
                bail!("Could not initialize collector {name}: {e}");
            }

            // If the collector provides known kernel types, meaning we have a
            // dynamic collector, retrieve and store them for later processing.
            if let Some(kt) = c.known_kernel_types() {
                kt.into_iter().for_each(|x| {
                    self.known_kernel_types.insert(x.to_string());
                });
            }

            self.collectors.insert(name.to_string(), c);
        }

        //  If auto-mode is used, print the list of collectors that were started.
        if auto_mode {
            info!(
                "Collector(s) started: {}",
                self.collectors
                    .keys()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>()
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
        if collect.probe_stack && collect.probes.is_empty() {
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
            // Skip probes not being compatible with the loaded collectors.
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
        collect.probes.iter().try_for_each(|p| -> Result<()> {
            probe_from_cli(p, filter)?
                .drain(..)
                .try_for_each(|p| self.probes.builder_mut()?.register_probe(p))?;
            Ok(())
        })?;

        Ok(())
    }

    /// Start the event retrieval for all collectors by calling
    /// their `start()` function.
    pub(super) fn start(&mut self, collect: &Collect) -> Result<()> {
        // Create factories.
        #[cfg_attr(test, allow(unused_mut))]
        let mut section_factories = section_factories()?;

        // Configure factories based on collectors config.
        if let Some(skb_factory) = section_factories.get_mut(&FactoryId::Skb) {
            skb_factory
                .as_any_mut()
                .downcast_mut::<SkbEventFactory>()
                .ok_or_else(|| anyhow!("Failed to downcast SkbEventFactory"))?
                .report_eth(
                    collect
                        .collector_args
                        .skb
                        .skb_sections
                        .iter()
                        .any(|s| s == "all" || s == "eth"),
                );
        }

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

        for (name, c) in &mut self.collectors {
            debug!("Starting collector {name}");
            if c.start().is_err() {
                warn!("Could not start collector {name}");
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

        for (name, c) in &mut self.collectors {
            debug!("Stopping collector {name}");
            if c.stop().is_err() {
                warn!("Could not stop collector {name}");
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
    pub(super) fn process(&mut self, collect: &Collect) -> Result<()> {
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
