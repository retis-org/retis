#[cfg(not(test))]
use std::os::fd::{AsFd, AsRawFd};
use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, error, info, warn};
use nix::{errno::Errno, mount::*, unistd::Uid};

use super::{
    cli::Collect,
    collector::{
        ct::CtCollector, dev::DevCollector, nft::NftCollector, ns::NsCollector, ovs::OvsCollector,
        skb::SkbCollector, skb_drop::SkbDropCollector, skb_tracking::SkbTrackingCollector,
    },
};
use crate::{
    bindings::{meta_filter_uapi, packet_filter_uapi},
    cli::{CliDisplayFormat, MainConfig},
    collect::collector::section_factories,
    core::{
        events::*,
        filters::{
            filters::{BpfFilter, Filter},
            meta::filter::FilterMeta,
            packets::filter::FilterPacket,
        },
        inspect::check::collection_prerequisites,
        kernel::Symbol,
        probe::{
            kernel::{probe_stack::*, utils::*},
            *,
        },
        tracking::{
            gc::TrackingGC, skb_tracking::init_tracking, stack_tracking::init_stack_tracking,
        },
    },
    events::{file::rotate::*, helpers::time::*, *},
    helpers::{file_rotate::*, signals::*},
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
        retis_factory: Arc<RetisEventsFactory>,
        section_factories: &mut SectionFactories,
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
    handles: Vec<thread::JoinHandle<()>>,
    known_kernel_types: HashSet<String>,
    run: Running,
    tracking_gc: Option<TrackingGC>,
    // Keep a reference on both the skb and stack tracking configuration maps.
    tracking_config_map: Option<libbpf_rs::MapHandle>,
    stack_tracking_config_map: Option<libbpf_rs::MapHandle>,
    // Monotonic clock offset stored once and reused.
    monotonic_offset: TimeSpec,
}

impl Collectors {
    pub(super) fn new() -> Result<Self> {
        let run = Running::new()?;
        let factory = BpfEventsFactory::new(run.clone())?;
        let probes = ProbeManager::new()?;

        Ok(Collectors {
            collectors: HashMap::new(),
            probes,
            factory,
            handles: Vec::new(),
            known_kernel_types: HashSet::new(),
            run,
            tracking_gc: None,
            tracking_config_map: None,
            stack_tracking_config_map: None,
            monotonic_offset: monotonic_clock_offset()?,
        })
    }

    /// Setup user defined input filter.
    fn setup_filters(probes: &mut ProbeBuilderManager, collect: &Collect) -> Result<()> {
        if let Some(f) = &collect.packet_filter {
            // L2 filter MUST always succeed. Any failure means we need to bail.
            let fb = FilterPacket::from_string_opt(f.to_string(), packet_filter_uapi::L2)?;

            probes.register_filter(Filter::Packet(
                packet_filter_uapi::L2,
                BpfFilter(fb.to_bytes()?),
            ))?;

            let mut loaded_info = "L2";
            // L3 filter is non mandatory.
            let fb = if f.contains("ether[") {
                debug!("Skipping L3 filter generation (ether[n:m] not allowed)");
                FilterPacket::reject_filter()
            } else {
                match FilterPacket::from_string_opt(f.to_string(), packet_filter_uapi::L3) {
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
                packet_filter_uapi::L3,
                BpfFilter(fb.to_bytes()?),
            ))?;

            info!("{loaded_info} packet filter(s) loaded");
        }

        if let Some(f) = &collect.meta_filter {
            let fb =
                FilterMeta::from_string(f.to_string()).map_err(|e| anyhow!("meta filter: {e}"))?;
            probes.register_filter(Filter::Meta(
                meta_filter_uapi::META,
                BpfFilter(fb.to_bytes()),
            ))?;
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

        // Mount tracefs if not already mounted (and if we can). This is
        // especially useful when running Retis in namespaces and containers.
        if collect.allow_system_changes {
            if let Some(mounted) = Self::try_mount("tracefs", "/sys/kernel/tracing") {
                if mounted {
                    self.run.add_drop_cb(|| {
                        if let Err(e) = umount("/sys/kernel/tracing") {
                            error!("Could not umount /sys/kernel/tracing: {e}");
                        }
                    });
                }
            } else if let Some(mounted) = Self::try_mount("debugfs", "/sys/kernel/debug") {
                if mounted {
                    self.run.add_drop_cb(|| {
                        if let Err(e) = umount("/sys/kernel/debug") {
                            error!("Could not umount /sys/kernel/debug: {e}");
                        }
                    });
                }
            }
        }

        // Check prerequisites.
        collection_prerequisites()
    }

    /// Try mounting a filesystem to a target directory. Returns:
    /// - Some(true) if the filesystem was mounted.
    /// - Some(false) if a filesystem is already mounted in the target.
    /// - None otherwise.
    fn try_mount(fs: &str, target: &str) -> Option<bool> {
        let err = mount(
            None::<&Path>,
            Path::new(target),
            Some(fs),
            MsFlags::empty(),
            None::<&str>,
        );

        match err {
            Ok(_) => {
                debug!("Mounted {fs} to {target}");
                Some(true)
            }
            Err(errno) => match errno {
                Errno::EBUSY => {
                    debug!("{fs} is already mounted to {target}");
                    Some(false)
                }
                _ => {
                    warn!("Could not mount {fs} to {target}: {errno}");
                    None
                }
            },
        }
    }

    fn init_collectors(
        &mut self,
        section_factories: &mut SectionFactories,
        events_factory: &Arc<RetisEventsFactory>,
        collect: &Collect,
    ) -> Result<()> {
        // Check if we need to report stack traces in the events.
        if collect.stack {
            self.probes
                .builder_mut()?
                .set_probe_opt(probe::ProbeOption::ReportStack)?;
        }
        if collect.probe_stack {
            self.probes
                .builder_mut()?
                .set_probe_opt(probe::ProbeOption::ProbeStack)?;
        }

        let collectors = &[
            "skb-tracking",
            "skb",
            "skb-drop",
            "ovs",
            "nft",
            "ct",
            "dev",
            "ns",
        ];
        let auto = collect.collectors.iter().any(|c| c == "auto");

        // Try initializing all collectors.
        for name in collectors {
            let mut c: Box<dyn Collector> = match *name {
                "skb-tracking" => Box::new(SkbTrackingCollector::new()?),
                "skb" => Box::new(SkbCollector::new()?),
                "skb-drop" => Box::new(SkbDropCollector::new()?),
                "ovs" => Box::new(OvsCollector::new()?),
                "nft" => Box::new(NftCollector::new()?),
                "ct" => Box::new(CtCollector::new()?),
                "dev" => Box::new(DevCollector::new()?),
                "ns" => Box::new(NsCollector::new()?),
                _ => bail!("Unknown collector {name}"),
            };

            let required = collect.collectors.iter().any(|c| c == *name);
            if !auto && !required {
                continue;
            }

            // Check if the collector can run (prerequisites are met).
            if let Err(e) = c.can_run(collect) {
                // Do not issue an error if the collector is not required.
                if !required {
                    debug!("Cannot run collector {name}: {e}");
                    continue;
                } else {
                    bail!("Cannot run collector {name}: {e}");
                }
            }

            c.init(
                collect,
                self.probes.builder_mut()?,
                Arc::clone(events_factory),
                section_factories,
            )
            .context(format!("Could not initialize the {name} collector"))?;

            // If the collector provides known kernel types, meaning we have a
            // dynamic collector, retrieve and store them for later processing.
            if let Some(kt) = c.known_kernel_types() {
                kt.into_iter().for_each(|x| {
                    self.known_kernel_types.insert(x.to_string());
                });
            }

            self.collectors.insert(name.to_string(), c);
        }

        //  If the default set of collectors is used, print the list of those
        //  started.
        if auto {
            info!(
                "Collector(s) started: {}",
                self.collectors
                    .keys()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
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

            section_factories
                .get_mut::<KernelEventFactory>(&crate::core::events::FactoryId::Kernel)?
                .stack_map = Some(sm);
        }

        if let Some(gc) = &mut self.tracking_gc {
            gc.start(self.run.clone())?;
        }

        Ok(())
    }

    fn config_filters(&mut self, collect: &Collect) -> Result<()> {
        // Initialize tracking & filters.
        if !cfg!(test) && self.known_kernel_types.contains("struct sk_buff *") {
            let (gc, map) = init_tracking(self.probes.builder_mut()?)?;
            self.tracking_gc = Some(gc);
            self.tracking_config_map = Some(map);
            self.stack_tracking_config_map = Some(init_stack_tracking(self.probes.builder_mut()?)?);
        }
        Self::setup_filters(self.probes.builder_mut()?, collect)
    }

    fn register_probes(&mut self, collect: &Collect, main_config: &MainConfig) -> Result<()> {
        // If no probe was explicitly set, find the right set automagically. In
        // addition check:
        // - No profile is used, this is to allow profiles to only use probes
        //   added by collectors (e.g. by skb-drop) and for better expectations.
        // - No collector is explicitly enabled, this is because collectors
        //   might add probes and we could be interested in getting those only.
        if main_config.profile.is_empty()
            && collect.probes.is_empty()
            && collect.collectors.eq(&["auto"])
        {
            let mut probes = if collect.probe_stack {
                // If --probe-stack is used, use skb:consume_skb & skb:kfree_skb
                // as a starting point (these should capture most if not all of
                // the packets and help moving up the stack).
                vec![
                    Probe::raw_tracepoint(Symbol::from_name("skb:consume_skb")?)?,
                    Probe::raw_tracepoint(Symbol::from_name("skb:kfree_skb")?)?,
                ]
            } else {
                // By default dump packets after the device in ingress and
                // before the device in egress; like AF_PACKET utilities.
                vec![
                    Probe::raw_tracepoint(Symbol::from_name("net:netif_receive_skb")?)?,
                    Probe::raw_tracepoint(Symbol::from_name("net:net_dev_start_xmit")?)?,
                ]
            };

            info!(
                "No probe(s) given: using {}",
                probes
                    .iter()
                    .map(|p| format!("{p}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            probes
                .drain(..)
                .try_for_each(|p| self.probes.builder_mut()?.register_probe(p))?;
        }

        // Cross probe check for option eligible to bypass filtering
        let skip_filter = collect.probes.iter().any(|p| {
            parse_cli_probe(p)
                .map(|(_, _, opts)| opts.contains(&ProbeOption::Ftrace))
                .unwrap_or(false)
        });

        // Setup user defined probes.
        let filter = |symbol: &Symbol, options: &HashSet<ProbeOption>| -> Result<bool> {
            let params = symbol.get_parameters()?;
            let has_known_type = self
                .known_kernel_types
                .iter()
                .any(|t| params.iter().any(|(_, p)| p == t));

            if options.contains(&ProbeOption::Ftrace)
                && !params.iter().any(|(_, p)| p == "struct sk_buff *")
            {
                bail!("ftrace option is invalid for '{symbol}': function has no sk_buff parameter");
            }

            // Allow inner probes on functions without known types.
            if skip_filter {
                return Ok(true);
            }

            // Skip probes not being compatible with the loaded collectors.
            if !has_known_type {
                info!(
                    "No probe was attached to {symbol} as no collector could retrieve data from it"
                );
            }

            Ok(has_known_type)
        };
        collect.probes.iter().try_for_each(|p| -> Result<()> {
            probe_from_cli(p, filter)?
                .drain(..)
                .try_for_each(|p| self.probes.builder_mut()?.register_probe(p))
        })
    }

    /// Start the event retrieval for all collectors by calling
    /// their `start()` function.
    #[cfg_attr(test, allow(unused_mut))]
    fn start_collectors(&mut self) -> Result<()> {
        // Attach probes and start collectors. We're using an open coded take &
        // replace combination. We could use a Cell<> instead but that would
        // complicate the use of self.probes (additional .get() calls) while
        // behaving the same.
        let probes = std::mem::take(&mut self.probes);
        let _ = std::mem::replace(&mut self.probes, probes.into_runtime()?);

        for (name, c) in &mut self.collectors {
            debug!("Starting collector {name}");
            if let Err(e) = c.start() {
                warn!("Could not start collector {name}: {e}");
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

        Ok(())
    }

    fn setup_formatters(
        &self,
        collect: &Collect,
        main_config: &MainConfig,
    ) -> Result<Vec<(EventFormatter, Box<dyn Write>)>> {
        let mut formatters = Vec::<(EventFormatter, Box<dyn Write>)>::new();

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
                .monotonic_offset(self.monotonic_offset)
                .print_ll(collect.print_ll);

            formatters.push((
                EventFormatter::new(self.run.clone(), 1, EventFormat::Text(format)),
                Box::new(io::stdout()),
            ));
        }

        // Write the events to a file if asked to.
        if let Some(out) = collect.out.as_ref() {
            formatters.push((
                EventFormatter::new(self.run.clone(), 1, EventFormat::Json),
                Box::new(
                    RotateWriter::new(
                        out,
                        match &collect.out_rotate {
                            Some(s) => Some(rotation_policy_from_str(s)?),
                            None => None,
                        },
                        collect.out_rotate_count,
                        &main_config.cmdline,
                        self.monotonic_offset,
                    )
                    .or_else(|e| bail!("Could not create or open '{}': {e}", out.display()))?,
                ),
            ));
        }

        Ok(formatters)
    }

    /// Starts the processing loop and block until we get a single SIGINT
    /// (e.g. ctrl+c), then return after properly cleaning up. This is the main
    /// collector cmd loop.
    pub(super) fn process(&mut self, collect: &Collect, main_config: &MainConfig) -> Result<()> {
        let (mut ecount, mut icount) = (0, 0);
        let threads = 1;

        let events_factory = Arc::new(RetisEventsFactory::default());
        let mut section_factories = section_factories()?;
        let mut formatters = self.setup_formatters(collect, main_config)?;

        self.init_collectors(&mut section_factories, &events_factory, collect)?;
        self.config_filters(collect)?;

        self.register_probes(collect, main_config)?;
        let (format, offset) = if collect.utc {
            (TimeFormat::UtcDate, Some(self.monotonic_offset))
        } else {
            Default::default()
        };
        self.factory.config_logger(format, offset);

        // Create the infrastructure to handle --probe-stack.
        let (psf_txc, psf_rxc) = crossbeam_channel::unbounded::<String>();
        let psf = ProbeStackFilter::new(
            collect.stack,
            Arc::new(
                self.probes
                    .builder()?
                    .probes()
                    .iter()
                    .filter(|p| p.has_option(ProbeOption::ReportStack))
                    .map(|p| format!("{p}"))
                    .collect(),
            ),
            Arc::new(self.known_kernel_types.clone()),
            psf_txc,
        );

        // Create the channel for conveying raw events. Reserve just enough
        // space for queuing a single raw event while another one is being
        // processed (the sending side is using a synchronous call).
        let (txc, rxc) = crossbeam_channel::bounded::<Vec<u8>>(threads * 2);

        // Threads to handle and parse raw events.
        let section_factories = Arc::new(section_factories);
        for i in 0..threads {
            let run = self.run.clone();
            let rxc = rxc.clone();
            let factories = Arc::clone(&section_factories);
            let formatters = formatters
                .iter()
                .map(|(f, _)| f.clone())
                .collect::<Vec<_>>();
            let psf = psf.clone();
            let probe_stack = collect.probe_stack;

            let thread = thread::Builder::new().name(format!("retis-event-{i}"));
            self.handles.push(thread.spawn(move || {
                while run.running() {
                    let raw = match rxc.recv_timeout(Duration::from_millis(CALL_TIMEOUT_MS)) {
                        Ok(raw) => raw,
                        _ => continue,
                    };

                    // Parse the raw event.
                    let mut event = match parse_raw_event(&raw, &factories) {
                        Ok(event) => event,
                        Err(e) => {
                            error!("Could not parse raw event: {e}");
                            continue;
                        }
                    };

                    if probe_stack {
                        if let Err(e) = psf.process_event(&mut event) {
                            warn!("Could not process event for --probe-stack: {e}");
                        }
                    }

                    // Process events.
                    if let Err(e) = formatters.iter().try_for_each(|f| f.process_event(&event)) {
                        error!("Could not format event {e}");
                    }
                }
            })?);
        }

        // Handle internal events generated at init time first, to make sure
        // they end up in the start of the output.
        if let Some(event) = events_factory.next_event() {
            formatters
                .iter()
                .try_for_each(|(f, _)| f.process_event(&event))?;
            icount += 1;
        }

        self.factory.start(txc)?;
        self.start_collectors()?;

        // Start the sub-command, if any.
        if let Some(cmd) = collect.cmd.to_owned() {
            let run = self.run.clone();
            let thread = thread::Builder::new().name("retis-collect-cmd".to_string());
            self.handles.push(thread.spawn(move || {
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
            })?);
        }

        let stop_count = collect.stop_after.unwrap_or_default();

        while self.run.running() {
            // First always try to dequeue all Retis events. This is not a
            // blocking call.
            if let Some(event) = events_factory.next_event() {
                formatters
                    .iter()
                    .try_for_each(|(f, _)| f.process_event(&event))?;
                icount += 1;
            }

            // Then process formatted eBPF events, if any.
            formatters.iter_mut().try_for_each(|(f, w)| -> Result<()> {
                if let Ok(EventResult::Event(event)) =
                    f.next(Duration::from_millis(CALL_TIMEOUT_MS))
                {
                    w.write_all(&event)?;
                    ecount += 1;
                }
                Ok(())
            })?;

            // Finally handle --probe-stack candidates, if any.
            #[cfg_attr(test, allow(unused_mut))]
            let mut new_probes = psf_rxc
                .try_iter()
                .map(|candidate| Symbol::from_name(&candidate).and_then(Probe::kprobe))
                .collect::<Result<Vec<_>>>()?;
            if !new_probes.is_empty() {
                let mgr = self.probes.runtime_mut()?;
                #[cfg(not(test))]
                new_probes
                    .drain(..)
                    .try_for_each(|p| mgr.add_generic_probe(p))?;
                mgr.attach_probes()?;
            }

            if stop_count > 0 && ecount - icount >= stop_count {
                self.run.terminate();
                info!("Reached stop count ({stop_count}), terminating...");
            }
        }

        // Drain remaining events.
        formatters.iter_mut().try_for_each(|(f, w)| -> Result<()> {
            while let Ok(EventResult::Event(event)) = f.next(Duration::from_millis(10)) {
                w.write_all(&event)?;
                ecount += 1;
            }
            Ok(())
        })?;

        formatters.iter_mut().try_for_each(|(_, w)| w.flush())?;
        debug!("{icount} internal event(s) processed");
        info!("{ecount} event(s) processed");

        self.stop()
    }
}
