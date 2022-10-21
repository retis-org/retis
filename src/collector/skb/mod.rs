//! # SkbCollector
//!
//! Provide a generic way to probe kernel functions and tracepoints (having a
//! `struct sk_buff *` as a parameter), to filter skbs, and to track them;
//! allowing to reconstruct their path in the Linux networking stack.

use anyhow::Result;
use clap::{Args, ValueEnum};
use serde::Deserialize;

use super::Collector;
use crate::core::probe::kernel;
use crate::config::Cli;



#[derive(Clone, Debug, Args, Deserialize)]
#[serde(default)]
#[serde(rename_all = "kebab-case")]
pub struct SkbConfig {
    /// Sets the skb collector in some (unexisting) mode
    #[arg(id="skb-mode", long)]
    mode : Option<SkbMode>,
} 

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum SkbMode {
    /// This is the default mode
    DefaultMode,
    /// This is one mode
    SomeMode,
    /// This is another mode
    SomeOtherMode,
}

impl Default for SkbConfig {
    fn default() -> Self {
        SkbConfig {mode: Some(SkbMode::DefaultMode)}
    }
}

pub(super) struct SkbCollector {
    config: SkbConfig,
}

impl Collector for SkbCollector {
    fn new(cli: &mut Cli) -> Result<SkbCollector> {
        cli.register_config::<SkbConfig>("skb")?;
        Ok(SkbCollector { config: SkbConfig::default() })
    }

    fn name(&self) -> &'static str {
        "skb"
    }

    fn init(&mut self, _kernel: &mut kernel::Kernel, cli: &mut Cli) -> Result<()> {
        self.config = cli.get_section("skb")?;
        
        println!("Skb in {:?} mode", self.config.mode);
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}
