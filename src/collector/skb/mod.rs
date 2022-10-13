//! # SkbCollector
//!
//! Provide a generic way to probe kernel functions and tracepoints (having a
//! `struct sk_buff *` as a parameter), to filter skbs, and to track them;
//! allowing to reconstruct their path in the Linux networking stack.

use anyhow::Result;

use super::Collector;
use crate::core::probe::{ProbeType, Probes};

#[path = "bpf/.out/hook.rs"]
mod hook;

pub(super) struct SkbCollector {}

impl Collector for SkbCollector {
    fn new() -> Result<SkbCollector> {
        Ok(SkbCollector {})
    }

    fn name(&self) -> &'static str {
        "skb"
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
