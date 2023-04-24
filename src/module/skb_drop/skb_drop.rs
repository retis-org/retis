use anyhow::Result;
use log::{error, info};

use super::skb_drop_hook;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{
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

    fn init(&mut self, _: &CliConfig, probes: &mut ProbeManager) -> Result<()> {
        let symbol = Symbol::from_name("kfree_skb_reason");
        // Did the probe failed because of an error or because it wasn't
        // available? In case we can't know, do not issue an error.
        match symbol {
            Ok(symbol) => {
                if let Err(e) = probes.add_probe(Probe::kprobe(symbol)?) {
                    error!("Could not attach to kfree_skb_reason: {}", e);
                }
            }
            Err(_) => info!("Skb drop reasons are not retrievable on this kernel"),
        }

        probes.register_kernel_hook(Hook::from(skb_drop_hook::DATA))
    }
}
