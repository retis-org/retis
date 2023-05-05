use anyhow::Result;

use super::nft_hook;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{
        kernel::Symbol,
        probe::{Hook, Probe, ProbeManager},
    },
};

pub(crate) struct NftCollector {}

impl Collector for NftCollector {
    fn new() -> Result<NftCollector> {
        Ok(NftCollector {})
    }

    fn register_cli(&self, _: &mut DynamicCommand) -> Result<()> {
        Ok(())
    }

    fn init(&mut self, _: &CliConfig, probes: &mut ProbeManager) -> Result<()> {
        let mut nft_probe = Probe::kprobe(Symbol::from_name("__nft_trace_packet")?)?;

        nft_probe.add_hook(Hook::from(nft_hook::DATA))?;
        probes.register_probe(nft_probe)?;

        Ok(())
    }
}
