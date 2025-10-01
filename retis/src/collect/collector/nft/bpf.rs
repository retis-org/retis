use anyhow::Result;

use crate::{
    bindings::nft_hook_uapi::*,
    core::events::{
        parse_single_raw_section, BpfRawSection, EventSectionFactory, FactoryId,
        RawEventSectionFactory,
    },
    event_section_factory,
    events::*,
    raw_to_string, raw_to_string_opt,
};

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

#[event_section_factory(FactoryId::Nft)]
#[derive(Default)]
pub(crate) struct NftEventFactory {}

impl RawEventSectionFactory for NftEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>, event: &mut Event) -> Result<()> {
        let mut nft = NftEvent::default();
        let raw = parse_single_raw_section::<nft_event>(&raw_sections)?;

        nft.table_name = raw_to_string!(&raw.table_name)?;
        nft.chain_name = raw_to_string!(&raw.chain_name)?;
        nft.table_handle = raw.t_handle;
        nft.chain_handle = raw.c_handle;
        nft.policy = raw.policy == 1;
        nft.rule_handle = match raw.r_handle {
            -1 => None,
            _ => Some(raw.r_handle),
        };
        match raw.verdict as i32 {
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
        .clone_into(&mut nft.verdict);

        // Destination chain is only valid for NFT_JUMP/NFT_GOTO.
        if raw.verdict as i32 == -3 || raw.verdict as i32 == -4 {
            nft.verdict_chain_name = raw_to_string_opt!(&raw.verdict_chain_name)?;
        }

        event.nft = Some(nft);
        Ok(())
    }
}
