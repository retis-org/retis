use std::{fmt, str};

use super::*;
use crate::event_section;

/// Nft event section
#[event_section("nft")]
pub(crate) struct NftEvent {
    pub table_name: String,
    pub chain_name: String,
    pub verdict: String,
    pub verdict_chain_name: Option<String>,
    pub table_handle: i64,
    pub chain_handle: i64,
    pub rule_handle: Option<i64>,
    pub policy: bool,
}

impl EventFmt for NftEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
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
