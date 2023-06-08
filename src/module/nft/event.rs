use std::{fmt, str};

use anyhow::Result;
use plain::Plain;

use crate::{
    core::events::{
        bpf::{parse_single_raw_section, BpfRawSection},
        *,
    },
    event_section, event_section_factory,
    module::ModuleId,
};

// Please keep in sync with its bpf counterpart under
// src/modules/nft/bpf/nft.bpf.c
const NFT_NAME_SIZE: usize = 128;

struct NftName([u8; NFT_NAME_SIZE]);

impl Default for NftName {
    fn default() -> Self {
        NftName([0; NFT_NAME_SIZE])
    }
}

impl NftName {
    fn to_string(&self) -> Result<String> {
        Ok(str::from_utf8(&self.0)?
            .trim_end_matches(char::from(0))
            .into())
    }

    fn to_string_opt(&self) -> Result<Option<String>> {
        let res = self.to_string()?;

        if res.is_empty() {
            return Ok(None);
        }

        Ok(Some(res))
    }
}

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
        if let Some(name) = &self.verdict_chain_name {
            write!(f, " chain {name}")?;
        }

        Ok(())
    }
}

// Please keep in sync with its bpf counterpart under
// src/modules/nft/bpf/nft.bpf.c
#[derive(Default)]
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
}

unsafe impl Plain for NftBpfEvent {}

#[derive(Default)]
#[event_section_factory(NftEvent)]
pub(crate) struct NftEventFactory {}

impl RawEventSectionFactory for NftEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut event = NftEvent::default();
        let raw = parse_single_raw_section::<NftBpfEvent>(ModuleId::Nft, raw_sections)?;

        event.table_name = raw.tn.to_string()?;
        event.chain_name = raw.cn.to_string()?;
        event.table_handle = raw.th;
        event.chain_handle = raw.ch;
        event.rule_handle = match raw.rh {
            -1 => None,
            _ => Some(raw.rh),
        };
        event.verdict = match raw.v {
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
        .to_owned();

        // Destination chain is only valid for NFT_JUMP/NFT_GOTO.
        if raw.v == -3 || raw.v == -4 {
            event.verdict_chain_name = raw.vcn.to_string_opt()?;
        }

        Ok(Box::new(event))
    }
}
