//! # Skb tracking
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

use std::{mem, thread, time::Duration};

use anyhow::{bail, Result};
use log::warn;
use nix::time;
use plain::Plain;

use crate::core::{
    kernel::Symbol,
    probe::{
        manager::{ProbeManager, PROBE_MAX},
        Probe,
        ProbeOption,
    },
    workaround::SendableMap,
};

// GC runs in a thread every SKB_TRACKING_GC_INTERVAL seconds to collect and
// remove old entries.
const SKB_TRACKING_GC_INTERVAL: u64 = 5;

// Time in seconds after entries in the skb tracking map are considered outdated
// and should be manually removed. It's a tradeoff between having consistent
// data and not having the map full of old entries. However, this logic
// shouldn't happen much — or it is a bug.
const TRACKING_OLD_LIMIT: u64 = 60;

fn config_map() -> Result<libbpf_rs::Map> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    // Please keep in sync with its BPF counterpart.
    libbpf_rs::Map::create(
        libbpf_rs::MapType::Hash,
        Some("tracking_config_map"),
        mem::size_of::<u64>() as u32,
        mem::size_of::<TrackingConfig>() as u32,
        PROBE_MAX as u32,
        &opts,
    )
    .or_else(|e| bail!("Could not create the tracking config map: {}", e))
}

fn tracking_map() -> Result<libbpf_rs::Map> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    // Please keep in sync with its BPF counterpart.
    libbpf_rs::Map::create(
        libbpf_rs::MapType::Hash,
        Some("tracking_map"),
        mem::size_of::<u64>() as u32,
        mem::size_of::<TrackingInfo>() as u32,
        8192,
        &opts,
    )
    .or_else(|e| bail!("Could not create the tracking map: {}", e))
}

pub(crate) fn init_tracking(probes: &mut ProbeManager) -> Result<()> {
    let config_map = config_map()?;
    let mut tracking_map = SendableMap::from(tracking_map()?);

    probes.reuse_map("tracking_config_map", config_map.fd())?;
    probes.reuse_map("tracking_map", tracking_map.get().fd())?;

    // For tracking skbs we only need the following two functions. First
    // track free events.
    let symbol = Symbol::from_name("skb_free_head")?;
    let key = symbol.addr()?.to_ne_bytes();
    let cfg = TrackingConfig {
        free: 1,
        inv_head: 0,
    };
    let cfg = unsafe { plain::as_bytes(&cfg) };
    config_map.update(&key, cfg, libbpf_rs::MapFlags::NO_EXIST)?;
    let mut p = Probe::kprobe(symbol)?;
    p.set_option(ProbeOption::NoGenericHook)?;
    probes.add_probe(p)?;

    // Then track invalidation head events.
    let symbol = Symbol::from_name("pskb_expand_head")?;
    let key = symbol.addr()?.to_ne_bytes();
    let cfg = TrackingConfig {
        free: 0,
        inv_head: 1,
    };
    let cfg = unsafe { plain::as_bytes(&cfg) };
    config_map.update(&key, cfg, libbpf_rs::MapFlags::NO_EXIST)?;
    let mut p = Probe::kprobe(symbol)?;
    p.set_option(ProbeOption::NoGenericHook)?;
    probes.add_probe(p)?;

    // Take care of gargabe collection of tracking info. This should be done
    // in the BPF part for most if not all skbs but we might lose some
    // information (and tracked functions might fail resulting in incorrect
    // information).
    thread::spawn(move || {
        let tracking_map = tracking_map.get_mut();

        loop {
            // Let's run every SKB_TRACKING_GC_INTERVAL seconds.
            thread::sleep(Duration::from_secs(SKB_TRACKING_GC_INTERVAL));
            let now = Duration::from(time::clock_gettime(time::ClockId::CLOCK_MONOTONIC).unwrap());

            // Loop through the tracking map entries and see if we see old
            // ones we should remove manually.
            let mut to_remove = Vec::new();
            for key in tracking_map.keys() {
                if let Ok(Some(raw)) = tracking_map.lookup(&key, libbpf_rs::MapFlags::ANY) {
                    // Get the tracking info associated with the entry.
                    let mut info = TrackingInfo::default();
                    plain::copy_from_bytes(&mut info, &raw[..]).unwrap();

                    // Remove old entries. Actually put them on a remove
                    // list as we can't live remove them here (we already
                    // have a reference to the map).
                    let last_seen = Duration::from_nanos(info.last_seen);
                    if now.saturating_sub(last_seen) > Duration::from_secs(TRACKING_OLD_LIMIT) {
                        to_remove.push(key);
                    }
                }
            }

            // Actually remove the outdated entries and issue a warning as
            // while it can be expected, it should not happen too often.
            for key in to_remove {
                tracking_map.delete(&key).ok();
                warn!(
                    "Removed old entry from skb tracking map: {:#x}",
                    u64::from_ne_bytes(key[..8].try_into().unwrap())
                );
            }
        }
    });

    Ok(())
}

// Please keep in sync with its BPF counterpart.
#[repr(C, packed)]
struct TrackingConfig {
    free: u8,
    inv_head: u8,
}

unsafe impl Plain for TrackingConfig {}

// Please keep in sync with its BPF counterpart.
#[derive(Default)]
#[repr(C, packed)]
struct TrackingInfo {
    timestamp: u64,
    last_seen: u64,
    orig_head: u64,
}

unsafe impl Plain for TrackingInfo {}
