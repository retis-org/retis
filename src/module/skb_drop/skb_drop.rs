use anyhow::{bail, Result};
use log::warn;

use super::skb_drop_hook;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{
        kernel::{inspect, Symbol},
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

    fn init(&mut self, _: &CliConfig, probes: &mut ProbeManager) -> Result<()> {
        // It makes no sense to use Retis on a kernel older enough not to have
        // the skb:kfree_skb tracepoint (it was introduced in 2009), we might
        // fail earlier anyway. So do not handle the error case nicely.
        let symbol = Symbol::from_name("skb:kfree_skb")?;

        // But we could see a kernel where skb:kfree_skb does not access a drop
        // reason, so check this and handle it nicely.
        match inspect::parameter_offset(&symbol, "enum skb_drop_reason") {
            Err(_) | Ok(None) => {
                warn!("Skb drop reasons are not retrievable on this kernel");
                return Ok(());
            }
            _ => (),
        }

        if let Err(e) = probes.add_probe(Probe::raw_tracepoint(symbol)?) {
            bail!("Could not attach to skb:kfree_skb: {}", e);
        }

        probes.register_kernel_hook(Hook::from(skb_drop_hook::DATA))
    }
}
