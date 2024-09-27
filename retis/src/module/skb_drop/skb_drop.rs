use std::sync::Arc;

use anyhow::{bail, Result};

use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{
        events::*,
        kernel::Symbol,
        probe::{Probe, ProbeBuilderManager},
    },
    events::SectionId,
    module::Module,
};

pub(crate) struct SkbDropModule {}

impl Collector for SkbDropModule {
    fn new() -> Result<Self> {
        Ok(Self {})
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(SectionId::SkbDrop)
    }

    fn can_run(&mut self, _: &CliConfig) -> Result<()> {
        // It makes no sense to use Retis on a kernel older enough not to have
        // the skb:kfree_skb tracepoint (it was introduced in 2009), we might
        // fail earlier anyway. So do not handle the error case nicely.
        Symbol::from_name("skb:kfree_skb")?;

        Ok(())
    }

    fn init(
        &mut self,
        _: &CliConfig,
        probes: &mut ProbeBuilderManager,
        _: Arc<RetisEventsFactory>,
    ) -> Result<()> {
        let probe = Probe::raw_tracepoint(Symbol::from_name("skb:kfree_skb")?)?;
        if let Err(e) = probes.register_probe(probe) {
            bail!("Could not attach to skb:kfree_skb: {}", e);
        }

        Ok(())
    }
}

impl Module for SkbDropModule {
    fn collector(&mut self) -> &mut dyn Collector {
        self
    }
}
