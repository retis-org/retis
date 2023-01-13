//! # SkbCollector
//!
//! One important goal of this tool is to follow packets in the stack, by
//! generating events at various points in the networking stack. To reconstruct
//! the flow of packets a way to uniquely identify them is more than needed.
//! Here we're targeting `struct sk_buff` and aim at generating unique
//! identifiers.
//!
//! The kernel does not offer such facility.
//!
//! Note: as the kernel changes, compilation decisions (which functions are
//! inlined for example) and internal API might change. For this reason making a
//! 100% accurate solution might not be possible and we chose to explicitly take
//! a safer path: trying hard to make the unique identifier work but leave room
//! for uncertainty.
//!
//! ## Unique identifier
//!
//! The socket buffer contains various metadata and a pointer to a memory area
//! used to store its data (`skb->head`). As moving data around is costly, this
//! memory area location is rarely changed during the lifetime of an skb. Also
//! the skb address itself is too volatile (clones, etc) to be stable in time.
//! The data location is a good candidate for the unique identifier.
//!
//! But using this alone wouldn't work as this memory location, after being
//! freed, might be reused at a later time and we would have two different
//! packets sharing the same id. To solve this issue we propose to:
//!
//! - Use the timestamp of the first time we saw a (unique) packet in its id.
//! - Track when a packet data is being freed and thus is available for reuse.
//! - Track the rare cases when the data location changes (for example when
//!   extending the data area) and reuse the initial data location in the id.
//!
//! The unique identifier is thus `(original_skb_head << 64 | initial_timestamp)`.
//!
//!
//! ## Clones
//!
//! Socket buffers can be cloned and we end up with multiple skb objects
//! pointing to the same data area. In such cases we'd still like to track those
//! as being the same packet while allowing to distinguish them. One easy way is
//! to provide the skb own address. We end up reporting `(unique_id, &skb)`.
//!
//! ## Internal tracking
//!
//! While the events will report `((original_skb_head << 64 | initial_timestamp), &skb)`
//! we can't directly use this in the kernel to track packets. We can however
//! directly use the data addresses as we know at a given point in time they'll
//! belong to a single packet. Thus to track packets we're using a map and the
//! data addresses as keys. The data itself contains metadata, including the
//! unique id itself).
//!
//! ## Proposed solution
//!
//! 1. We don't need to react to allocation events specifically. A packet will
//!    be matched at some point and we can consider this as the initial event
//!    triggering the identification logic. It's not an issue as we're not
//!    refcounting the packets ourselves.
//!
//! 2. We don't need to react to clone events as the data address won't change
//!    and we'll be reusing the unique id. A new skb will show in the logs and
//!    we'll be able to both identify it as being part of the flow and as being
//!    a clone (different skb address). Fast clones are not special either.
//!
//! 3. To track data address modifications we need to map those packets to the
//!    original unique id. In addition, we can't know the new data location when
//!    it is being modified and we need a temporary one until we see the packet
//!    again (with its new data address). For this we'll use the skb address
//!    directly.
//!
//!    Notes:
//!    - This can't conflict with other keys (key are all memory addresses).
//!    - If the data modification function fails and we don't track this, a
//!      stale entry will stay until being garbage collected (see below).
//!
//! 4. When the data area is freed (or marked for reuse) we should stop tracking
//!    it. As we allow to miss some events to have a more robust design, we're
//!    garbage collecting old events from the tracking map (such events should
//!    be fairly rare, otherwise it's a bug).

// Re-export skb_tracking.rs
#[allow(clippy::module_inception)]
pub(crate) mod skb_tracking;
pub(crate) use skb_tracking::*;

mod tracking_hook {
    include!("bpf/.out/tracking_hook.rs");
}
