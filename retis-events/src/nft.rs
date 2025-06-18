use std::{fmt, str};

use super::*;
use crate::{event_section, Formatter};

/// Nftables section.
#[event_section]
#[derive(Default)]
pub struct NftEvent {
    /// Table name.
    pub table_name: String,
    /// Chain name.
    pub chain_name: String,
    /// Verdict.
    pub verdict: String,
    /// Verdict chain name.
    pub verdict_chain_name: Option<String>,
    /// Table handle.
    pub table_handle: i64,
    /// Chain handle.
    pub chain_handle: i64,
    /// Rule handle.
    pub rule_handle: Option<i64>,
    /// Policy.
    pub policy: bool,
}

impl EventFmt for NftEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(
            f,
            "table {} ({}) chain {} ({})",
            self.table_name, self.table_handle, self.chain_name, self.chain_handle,
        )?;

        if let Some(rule) = self.rule_handle {
            write!(f, " handle {rule}")?;
        }

        write!(f, " {}", self.verdict)?;

        if self.policy {
            write!(f, " (policy)")?;
        }

        if let Some(name) = &self.verdict_chain_name {
            write!(f, " chain {name}")?;
        }

        Ok(())
    }
}
