use std::sync::Arc;

use anyhow::{bail, Result};
use log::warn;

use super::skb_drop_hook;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::collector::Module,
    collect::Collector,
    core::{
        events::*,
        inspect::{inspector, kernel_version::KernelVersionReq},
        kernel::Symbol,
        probe::{Hook, Probe, ProbeBuilderManager},
    },
    events::SectionId,
};

pub(crate) struct SkbDropModule {
    reasons_available: bool,
}

impl Collector for SkbDropModule {
    fn new() -> Result<Self> {
        Ok(Self {
            reasons_available: true,
        })
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec![
            "enum skb_drop_reason",
            "enum mac80211_drop_reason",
            "enum ovs_drop_reason",
        ])
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(SectionId::SkbDrop)
    }

    fn can_run(&mut self, _: &CliConfig) -> Result<()> {
        let inspector = inspector()?;

        // It makes no sense to use Retis on a kernel older enough not to have
        // the skb:kfree_skb tracepoint (it was introduced in 2009), we might
        // fail earlier anyway. So do not handle the error case nicely.
        let symbol = Symbol::from_name("skb:kfree_skb")?;

        // But we could see a kernel where skb:kfree_skb does not access a drop
        // reason, so check this and handle it nicely.
        match inspector
            .kernel
            .parameter_offset(&symbol, "enum skb_drop_reason")
        {
            Err(_) | Ok(None) => {
                let kver = inspector.kernel.version();

                // Skb drop reasons were introduced in kernel v5.17 and are not
                // a build config option; if not found in such case bail out. On
                // older kernel, still allow the collector to run, with a
                // warning.
                if KernelVersionReq::parse(">= 5.17")?.matches(kver) {
                    bail!("Could not retrieve skb drop reasons from the kernel");
                } else {
                    warn!("This kernel doesn't provide skb drop reasons");
                    self.reasons_available = false;
                }
            }
            _ => (),
        }

        Ok(())
    }

    fn init(
        &mut self,
        _: &CliConfig,
        probes: &mut ProbeBuilderManager,
        _: Arc<RetisEventsFactory>,
    ) -> Result<()> {
        let mut probe = Probe::raw_tracepoint(Symbol::from_name("skb:kfree_skb")?)?;
        let hook = Hook::from(skb_drop_hook::DATA);

        if self.reasons_available {
            probes.register_kernel_hook(hook)?;
        } else {
            // If the kernel doesn't support drop reasons, only attach the hook
            // to the skb:kfree_skb tracepoint (otherwise we would have a fake
            // reason attached to all events).
            probe.add_hook(hook)?;
        }

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
