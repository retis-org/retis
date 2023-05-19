/// Global configuration passed down the BPF part.
#[repr(C, packed)]
pub(super) struct NftConfig {
    /// Bitfield of events to collect based on the verdict.
    /// The values follow the kernel definitions as they are uapi.
    pub verdicts: u64,
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
