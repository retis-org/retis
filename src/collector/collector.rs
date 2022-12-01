use anyhow::Result;

use super::group::Group;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    core::{events::bpf::BpfEvents, probe},
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
}

impl Collectors {
    /// Get a new collectors instance by registering all the collectors.
    pub(crate) fn new() -> Result<Collectors> {
        let mut group = Group::new()?;

        // Register all collectors here.
        group
            .register(Box::new(SkbTrackingCollector::new()?))?
            .register(Box::new(SkbCollector::new()?))?
            .register(Box::new(OvsCollector::new()?))?;

        Ok(Collectors{
            group,
        })
    }

    /// Register the collect command line arguments.
    pub(crate) fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        self.group.register_cli(cmd)
    }

    /// Initialize the collectors and starts the event collection. This function
    /// is blocking and does not return.
    pub(crate) fn init_and_collect(&mut self, cli: &CliConfig) -> Result<()> {
        self.group.init(cli)?;
        self.group.start(cli)?;

        loop {
            let event = self.group.poll_event()?;
            println!("{}", event.to_json());
        }
        #[allow(unreachable_code)]
        Ok(())
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
