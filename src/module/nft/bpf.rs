use anyhow::Result;

use crate::{
    event_byte_array,
    events::{
        bpf::{parse_single_raw_section, BpfRawSection},
        *,
    },
    EventSectionFactory,
};

// Please keep in sync with its bpf counterpart under
// src/modules/nft/bpf/nft.bpf.c
const NFT_NAME_SIZE: usize = 128;
event_byte_array!(NftName, NFT_NAME_SIZE);
/// Nft specific parameter offsets; keep in sync with its BPF counterpart in
/// bpf/nft.bpf.c
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub(super) struct NftOffsets {
    pub(super) nft_chain: i8,
    pub(super) nft_rule: i8,
    pub(super) nft_verdict: i8,
    pub(super) nft_type: i8,
}

impl Default for NftOffsets {
    fn default() -> NftOffsets {
        NftOffsets {
            nft_chain: -1,
            nft_rule: -1,
            nft_verdict: -1,
            nft_type: -1,
        }
    }
}

/// Global configuration passed down the BPF part.
#[derive(Default)]
#[repr(C, packed)]
pub(super) struct NftConfig {
    /// Bitfield of events to collect based on the verdict.
    /// The values follow the kernel definitions as they are uapi.
    pub(super) verdicts: u64,
    pub(super) offsets: NftOffsets,
}

/// Allowed verdicts in an event.
/// They are the actual verdict values, scaled to be positive.
/// Actual verdicts value are safe to use as they are uapi.
/// See include/uapi/linux/{netfilter/nf_tables.h,netfilter.h}.
pub(super) const VERD_RETURN: u64 = 0;
pub(super) const VERD_GOTO: u64 = 1;
pub(super) const VERD_JUMP: u64 = 2;
pub(super) const VERD_BREAK: u64 = 3;
pub(super) const VERD_CONTINUE: u64 = 4;
pub(super) const VERD_DROP: u64 = 5;
pub(super) const VERD_ACCEPT: u64 = 6;
// NF_STOLEN implies no skb which in turn means we're unable to
// filter, so NF_STOLEN could be skipped if filtering is enabled.
pub(super) const VERD_STOLEN: u64 = 7;
pub(super) const VERD_QUEUE: u64 = 8;
pub(super) const VERD_REPEAT: u64 = 9;
pub(super) const VERD_MAX: u64 = VERD_REPEAT;

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

#[derive(Default, EventSectionFactory)]
pub(crate) struct NftEventFactory {}

impl RawEventSectionFactory for NftEventFactory {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut event = NftEvent::default();
        let raw = parse_single_raw_section::<NftBpfEvent>(SectionId::Nft, &raw_sections)?;

        event.table_name = raw.tn.to_string()?;
        event.chain_name = raw.cn.to_string()?;
        event.table_handle = raw.th;
        event.chain_handle = raw.ch;
        event.policy = raw.p == 1;
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
