use std::{fmt, str};

use anyhow::Result;

use crate::{
    event_byte_array, event_section, event_section_factory,
    events::{
        bpf::{parse_single_raw_section, BpfRawSection},
        *,
    },
    module::ModuleId,
};

// Please keep in sync with its bpf counterpart under
// src/modules/nft/bpf/nft.bpf.c
const NFT_NAME_SIZE: usize = 128;

event_byte_array!(NftName, NFT_NAME_SIZE);

/// Nft event section
#[event_section]
pub(crate) struct NftEvent {
    table_name: String,
    chain_name: String,
    verdict: String,
    verdict_chain_name: Option<String>,
    table_handle: i64,
    chain_handle: i64,
    rule_handle: Option<i64>,
    policy: bool,
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

// Please keep in sync with its bpf counterpart under
// src/modules/nft/bpf/nft.bpf.c
#[repr(C, packed)]
struct NftBpfEvent {
    /// Table name.
    tn: NftName,
    /// Chain name.
    cn: NftName,
    /// Verdict.
    v: i32,
    /// Verdict chain name.
    vcn: NftName,
    /// Table handle
    th: i64,
    /// Chain handle
    ch: i64,
    /// Rule handle
    rh: i64,
    /// Verdict refers to the policy
    p: u8,
}

#[derive(Default)]
#[event_section_factory(NftEvent)]
pub(crate) struct NftEventFactory {}

impl RawEventSectionFactory for NftEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut event = NftEvent::default();
        let raw = parse_single_raw_section::<NftBpfEvent>(ModuleId::Nft, &raw_sections)?;

        event.table_name = raw.tn.to_string()?;
        event.chain_name = raw.cn.to_string()?;
        event.table_handle = raw.th;
        event.chain_handle = raw.ch;
        event.policy = raw.p == 1;
        event.rule_handle = match raw.rh {
            -1 => None,
            _ => Some(raw.rh),
        };
        match raw.v {
            -1 => "continue",
            -2 => "break",
            -3 => "jump",
            -4 => "goto",
            -5 => "return",
            0 => "drop",
            1 => "accept",
            2 => "stolen",
            3 => "queue",
            4 => "repeat",
            /* NF_STOP is deprecated. */
            5 => "stop",
            _ => "unknown",
        }
        .clone_into(&mut event.verdict);

        // Destination chain is only valid for NFT_JUMP/NFT_GOTO.
        if raw.v == -3 || raw.v == -4 {
            event.verdict_chain_name = raw.vcn.to_string_opt()?;
        }

        Ok(Box::new(event))
    }
}
