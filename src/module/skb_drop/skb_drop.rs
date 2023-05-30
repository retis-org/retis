use anyhow::{bail, Result};

use super::skb_drop_hook;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{
        inspect::inspector,
        kernel::Symbol,
        probe::{Hook, Probe, ProbeManager},
    },
    module::ModuleId,
};

pub(crate) struct SkbDropCollector {}

impl Collector for SkbDropCollector {
    fn new() -> Result<Self> {
        Ok(Self {})
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["enum skb_drop_reason"])
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(ModuleId::SkbDrop)
    }

    fn can_run(&mut self, _: &CliConfig) -> Result<()> {
        // It makes no sense to use Retis on a kernel older enough not to have
        // the skb:kfree_skb tracepoint (it was introduced in 2009), we might
        // fail earlier anyway. So do not handle the error case nicely.
        let symbol = Symbol::from_name("skb:kfree_skb")?;

        // But we could see a kernel where skb:kfree_skb does not access a drop
        // reason, so check this and handle it nicely.
        match inspector()?
            .kernel
            .parameter_offset(&symbol, "enum skb_drop_reason")
        {
            Err(_) | Ok(None) => bail!("Skb drop reasons are not retrievable on this kernel"),
            _ => (),
        }

        Ok(())
    }

    fn init(&mut self, _: &CliConfig, probes: &mut ProbeManager) -> Result<()> {
        let symbol = Symbol::from_name("skb:kfree_skb")?;

        if let Err(e) = probes.register_probe(Probe::raw_tracepoint(symbol)?) {
            bail!("Could not attach to skb:kfree_skb: {}", e);
        }

        probes.register_kernel_hook(Hook::from(skb_drop_hook::DATA))
    }
}
