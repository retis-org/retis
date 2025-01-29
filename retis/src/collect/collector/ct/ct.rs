use std::sync::Arc;

use anyhow::{bail, Result};

use super::ct_hook;
use crate::{
    collect::{cli::Collect, Collector},
    core::{
        events::*,
        inspect,
        probe::{Hook, ProbeBuilderManager},
    },
};

#[derive(Default)]
pub(crate) struct CtCollector {}

impl Collector for CtCollector {
    fn new() -> Result<Self> {
        Ok(Self::default())
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct sk_buff *"])
    }

    fn can_run(&mut self, _: &Collect) -> Result<()> {
        let kernel = &inspect::inspector()?.kernel;

        match kernel.get_config_option("CONFIG_NF_CONNTRACK") {
            Ok(Some("y")) => (),
            Ok(Some("m")) => {
                if kernel.is_module_loaded("nf_conntrack") == Some(false) {
                    bail!("'nf_conntrack' is not loaded");
                }
            }
            // If the Kernel Config is not available, the collector is not guaranteed
            // to work, but let's try.
            Err(_) => (),
            _ => bail!("This kernel does not support connection tracking"),
        }
        Ok(())
    }

    fn init(
        &mut self,
        _: &Collect,
        probes: &mut ProbeBuilderManager,
        _: Arc<RetisEventsFactory>,
    ) -> Result<()> {
        // Register our generic conntrack hook.
        probes.register_kernel_hook(Hook::from(ct_hook::DATA))
    }
}
