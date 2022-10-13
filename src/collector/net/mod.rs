//! # NetCollector

use anyhow::Result;

use super::Collector;
use crate::core::probe::{ProbeType, Probes};

#[path = "bpf/.out/hook.rs"]
mod hook;

pub(super) struct NetCollector {}

impl Collector for NetCollector {
    fn new() -> Result<NetCollector> {
        Ok(NetCollector {})
    }

    fn name(&self) -> &'static str {
        "net"
    }

    fn init(&mut self, probe: &mut Probes) -> Result<()> {
        probe.kernel.add_hook(hook::DATA)?;
        probe
            .kernel
            .add_probe(ProbeType::Kprobe, "kfree_skb_reason")?;

        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}
