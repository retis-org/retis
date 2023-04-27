use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    thread::JoinHandle,
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use log::{debug, info, warn};
use signal_hook::low_level::signal_name;

use super::cli::{Collect, CollectArgs, OutputFormat};
#[cfg(not(test))]
use crate::core::probe::kernel::{config::init_stack_map, kernel::KernelEventFactory};
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig, FullCli},
    core::{
        events::{bpf::BpfEventsFactory, format, EventFactory},
        filters::{
            filters::{BpfFilter, Filter},
            packets::filter::FilterPacket,
        },
        kernel::{symbol::matching_functions_to_symbols, Symbol},
        probe::{self, Probe, ProbeManager},
        signals::Running,
        tracking::skb_tracking::init_tracking,
    },
    module::{get_modules, ModuleId, Modules},
    output,
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
    probes: probe::ProbeManager,
    cli: CliConfig,
    factory: Box<dyn EventFactory>,
    known_kernel_types: HashSet<String>,
    gc_handle: Option<JoinHandle<()>>,
    run: Running,
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
            gc_handle: None,
            run: Running::new(),
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
        for sig in signal_hook::consts::TERM_SIGNALS {
            debug!("Registering {}", signal_name(*sig).unwrap());
            self.run.register_signal(*sig)?;
        }

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
            self.gc_handle = init_tracking(&mut self.probes, self.run.clone())?;
        }
        Self::setup_filters(&mut self.probes, collect)?;

        // Setup user defined probes.
        let mut probes = Vec::new();
        collect
            .args()?
            .probes
            .iter()
            .try_for_each(|p| -> Result<()> {
                probes.append(&mut self.parse_probe(p)?);
                Ok(())
            })?;
        probes
            .drain(..)
            .try_for_each(|p| self.probes.register_probe(p))?;

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

    /// Stop the event retrieval for all collectors in the group by calling
    /// their `stop()` function. All the collectors are in charge to clean-up
    /// their temporary side effects and exit gracefully.
    fn stop(&mut self) -> Result<()> {
        self.modules.collectors().iter_mut().for_each(|(id, c)| {
            debug!("Stopping {}", id.to_str());
            if c.stop().is_err() {
                warn!("Could not stop '{}'", id.to_str());
            }
        });

        // We're not actually stopping but just joining. The actual
        // termination got performed implicitly by the signal handler.
        // The print-out is just for consistency.
        debug!("Stopping tracking gc");
        if let Some(gc) = self.gc_handle.take() {
            gc.join().or_else(|_| bail!("failed to stop tracking gc"))?;
        }

        debug!("Stopping events");
        self.factory.stop()?;

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
            .ok_or_else(|| anyhow!("wrong subcommand"))?
            .args()?;

        let mut outputs = Self::get_outputs(collect)?;

        while self.run.running() {
            match self.factory.next_event(Some(Duration::from_secs(1)))? {
                Some(event) => outputs.iter_mut().try_for_each(|p| p.output_one(&event))?,
                None => continue,
            }
        }

        outputs.iter_mut().try_for_each(|p| p.flush())?;
        self.stop()
    }

    /// Parse a user defined probe (through cli parameters) and extract its type and
    /// target.
    fn parse_probe(&self, probe: &str) -> Result<Vec<Probe>> {
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

        // Convert the target to a list of matching ones for probe types
        // supporting it.
        let mut symbols = match type_str {
            "kprobe" => matching_functions_to_symbols(target)?,
            _ => vec![Symbol::from_name(target)?],
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
            if !valid {
                warn!(
                    "A probe to symbol {} is attached but no collector will retrieve data from it, only generic information will be retrieved",
                    symbol
                );
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

    /// Given a Formatter and cli arguments, get a list of output outputs, for
    /// later event output processing.
    fn get_outputs(args: &CollectArgs) -> Result<Vec<Box<dyn output::Output>>> {
        let mut outputs = Vec::<Box<dyn output::Output>>::new();

        // Write the events to a file if asked to.
        if let Some(out) = args.out.as_ref() {
            // File-based output is always json.
            let formatter = Box::<format::JsonFormat>::default();
            let mut writers: Vec<Box<dyn Write>> = Vec::new();
            writers.push(Box::new(BufWriter::new(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(out)
                    .or_else(|_| bail!("Could not create or open '{}'", out.display()))?,
            )));

            // If the stdout format is also json, share the formatter.
            if args.print {
                if let OutputFormat::Json = args.format {
                    writers.push(Box::new(io::stdout()));
                }
            }
            outputs.push(Box::new(output::FormatAndWrite::new(formatter, writers)));
        }

        // Write events to stdout if we don't write to a file (--out) or if
        // explicitly asked to (--print) with a non-json format.
        if args.out.is_none() || args.print {
            let formatter: Option<Box<dyn output::Formatter>> = match args.format {
                OutputFormat::Json => match args.out {
                    // If output was requested, a single JsonFormatter is used and share for both
                    // outputs. No need to add another one.
                    Some(_) => None,
                    None => Some(Box::<format::JsonFormat>::default()),
                },
                OutputFormat::Text => Some(Box::<format::TextFormat>::default()),
            };
            if let Some(f) = formatter {
                let writer: Box<dyn Write> = Box::new(io::stdout());
                outputs.push(Box::new(output::FormatAndWrite::new(f, vec![writer])));
            }
        }

        Ok(outputs)
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
        core::events::{bpf::BpfRawSection, format::*, *},
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

    impl EventFormat for TestEvent {
        fn format(&self, _format: &FormatOpts) -> String {
            String::new()
        }
    }

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
        assert!(collectors.parse_probe("tcp_v6_*").is_ok());
        assert!(collectors.parse_probe("kprobe:tcp_v6_*").is_ok());
        assert!(collectors.parse_probe("kprobe:tcp_v6_*")?.len() > 0);

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

        // Invalid probe: wildcard not supported.
        assert!(collectors.parse_probe("kretprobe:tcp_*").is_err());
        assert!(collectors.parse_probe("tp:kfree_*").is_err());

        Ok(())
    }
}
