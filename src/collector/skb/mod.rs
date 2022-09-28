//! # SkbCollector
//!
//! Provide a generic way to probe kernel functions and tracepoints (having a
//! `struct sk_buff *` as a parameter), to filter skbs, and to track them;
//! allowing to reconstruct their path in the Linux networking stack.
//!
//! This collector is somehow special as it allows other collectors to register
//! extra hooks to retrieve additional information and enrich SKB events.

use anyhow::Result;

use crate::collector::Collector;

pub(super) struct SkbCollector {
}

impl Collector for SkbCollector {
    fn new() -> Result<SkbCollector> {
        Ok(SkbCollector {})
    }

    fn name(&self) -> &'static str {
        "skb"
    }

    fn init(&mut self) -> Result<()> {
        Ok(())
    }

    fn start (&mut self) -> Result<()> {
        Ok(())
    }
}
