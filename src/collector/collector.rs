use anyhow::{anyhow, bail, Result};

use super::{cli::Collect, group::Group};
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    core::{
        events::bpf::BpfEvents,
        kernel::Symbol,
        probe::{self, kernel::ProbeType},
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
    ///Register command line arguments on the provided DynamicCommand object
    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()>;
    /// Return the name of the collector. It *has* to be unique among all the
    /// collectors.
    fn name(&self) -> &'static str;
    /// Initialize the collector, likely to be used to pass configuration data
    /// such as filters or command line arguments. We need to split the new &
    /// the init phase for collectors, to allow giving information to the core
    /// as part of the collector registration and only then feed the collector
    /// with data coming from the core. Checks for the mandatory part of the
    /// collector should be done here.
    fn init(
        &mut self,
        cli: &CliConfig,
        kernel: &mut probe::Kernel,
        events: &mut BpfEvents,
    ) -> Result<()>;
    /// Start the group of events (non-probes).
    fn start(&mut self) -> Result<()>;
}

/// This is the main object responsible of collecting events, using cli
/// parameters and a group of per-target collectors. This is the entry point of
/// the collector module.
pub(crate) struct Collectors {
    group: Group,
    kernel: probe::Kernel,
    events: BpfEvents,
}

impl Collectors {
    /// Get a new collectors instance by registering all the collectors.
    pub(crate) fn new() -> Result<Collectors> {
        let mut group = Group::default();

        // Register all collectors here.
        group
            .register(Box::new(SkbTrackingCollector::new()?))?
            .register(Box::new(SkbCollector::new()?))?
            .register(Box::new(OvsCollector::new()?))?;

        let events = BpfEvents::new()?;
        let kernel = probe::Kernel::new(&events)?;

        Ok(Collectors {
            group,
            kernel,
            events,
        })
    }

    /// Register the collect command line arguments.
    pub(crate) fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        self.group.register_cli(cmd)
    }

    /// Initialize the collectors and starts the event collection. This function
    /// is blocking and does not return.
    pub(crate) fn init_and_collect(&mut self, cli: &CliConfig) -> Result<()> {
        // First process our own cli parameters.
        let collect = cli
            .subcommand
            .as_any()
            .downcast_ref::<Collect>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?;

        probe::common::set_ebpf_debug(collect.args()?.ebpf_debug.unwrap_or(false))?;
        self.setup_probes(collect)?;

        // Then init all the collectors in our group.
        self.group.init(cli, &mut self.kernel, &mut self.events)?;

        // Finally start the polling logic, the collectors, attach the probes.
        self.events.start_polling()?;
        self.kernel.attach()?;
        self.group.start()?;

        // Last step, we can poll and process the events.
        loop {
            let event = self.events.poll()?;
            println!("{}", event.to_json());
        }
        #[allow(unreachable_code)]
        Ok(())
    }

    /// Setup user defined probes (configured through cmdline arguments).
    fn setup_probes(&mut self, collect: &Collect) -> Result<()> {
        // Go through the user defined probes.
        for probe in collect.args()?.probes.iter() {
            let (r#type, target) = parse_probe(probe)?;
            let symbol = Symbol::from_name(target)?;

            // Check if the target has access to an skb.
            if symbol.parameter_offset("struct sk_buff *")?.is_none() {
                bail!("Probe target {} does not have access to an skb", probe);
            }

            // Seems OK, probe it.
            self.kernel.add_probe_to_symbol(r#type, symbol)?;
        }
        Ok(())
    }
}

/// Parse a user defined probe (through cli parameters) and extract its type and
/// target.
fn parse_probe(probe: &str) -> Result<(ProbeType, &str)> {
    match probe.split_once(':') {
        Some((type_str, target)) => {
            let r#type = match type_str {
                "kprobe" => ProbeType::Kprobe,
                "tp" => ProbeType::RawTracepoint,
                x => bail!("Invalid TYPE {}. See the help.", x),
            };
            Ok((r#type, target))
        }
        None => bail!("No TYPE given. See the help."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_collectors() {
        assert!(Collectors::new().is_ok());
    }
}
