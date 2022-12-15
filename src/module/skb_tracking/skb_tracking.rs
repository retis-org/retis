use std::{mem, thread, time::Duration};

use anyhow::{bail, Result};
use log::{error, info, warn};
use nix::time;
use plain::Plain;

use super::tracking_hook;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{
        events::{
            bpf::{BpfEventOwner, BpfEvents},
            EventField,
        },
        kernel::Symbol,
        probe::{
            manager::{ProbeManager, PROBE_MAX},
            Hook, Probe,
        },
        workaround::SendableMap,
    },
    event_field,
};

const SKB_TRACKING_COLLECTOR: &str = "skb-tracking";

// GC runs in a thread every SKB_TRACKING_GC_INTERVAL seconds to collect and
// remove old entries.
const SKB_TRACKING_GC_INTERVAL: u64 = 5;

// Time in seconds after entries in the skb tracking map are considered outdated
// and should be manually removed. It's a tradeoff between having consistent
// data and not having the map full of old entries. However, this logic
// shouldn't happen much — or it is a bug.
const TRACKING_OLD_LIMIT: u64 = 60;

// Tracking event. Please keep in sync with its BPF counterpart.
#[derive(Default)]
#[repr(C, packed)]
struct SkbTrackingEvent {
    orig_head: u64,
    timestamp: u64,
    skb: u64,
    drop_reason: u32,
}
unsafe impl Plain for SkbTrackingEvent {}

#[derive(Default)]
pub(crate) struct SkbTrackingCollector {
    garbage_collector: Option<thread::JoinHandle<()>>,
}

impl Collector for SkbTrackingCollector {
    fn new() -> Result<SkbTrackingCollector> {
        Ok(SkbTrackingCollector::default())
    }

    fn name(&self) -> &'static str {
        SKB_TRACKING_COLLECTOR
    }

    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        Some(vec!["struct sk_buff *"])
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(SKB_TRACKING_COLLECTOR)
    }

    fn init(
        &mut self,
        _: &CliConfig,
        probes: &mut ProbeManager,
        events: &mut BpfEvents,
    ) -> Result<()> {
        events.register_unmarshaler(
            BpfEventOwner::CollectorSkbTracking,
            Box::new(|raw_section, fields| {
                if raw_section.header.data_type != 1 {
                    bail!("Unknown data type");
                }

                if raw_section.data.len() != mem::size_of::<SkbTrackingEvent>() {
                    bail!(
                        "Section data is not the expected size {} != {}",
                        raw_section.data.len(),
                        mem::size_of::<SkbTrackingEvent>(),
                    );
                }

                let mut event = SkbTrackingEvent::default();
                plain::copy_from_bytes(&mut event, &raw_section.data)
                    .or_else(|_| bail!("Could not parse the raw section"))?;

                fields.push(event_field!("orig_head", event.orig_head));
                fields.push(event_field!("timestamp", event.timestamp));
                fields.push(event_field!("skb", event.skb));
                fields.push(event_field!("drop_reason", event.drop_reason));
                Ok(())
            }),
        )?;

        self.init_tracking(probes)?;

        // We'd like to track free reasons as well.
        let symbol = Symbol::from_name("kfree_skb_reason");
        // Did the probe failed because of an error or because it wasn't
        // available? In case we can't know, do not issue an error.
        match symbol.is_ok() {
            true => {
                // Unwrap as we just checked the value is valid.

                if let Err(e) = probes.add_probe(Probe::kprobe(symbol.unwrap())?) {
                    error!("Could not attach to kfree_skb_reason: {}", e);
                }
            }
            false => info!("Skb drop reasons are not retrievable on this kernel"),
        }

        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}

impl SkbTrackingCollector {
    fn tracking_config_map() -> Result<libbpf_rs::Map> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        // Please keep in sync with its BPF counterpart in
        // bpf/tracking_hook.ebpf.c
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

        // Please keep in sync with its BPF counterpart in
        // bpf/tracking_hook.ebpf.c
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

    fn init_tracking(&mut self, probes: &mut ProbeManager) -> Result<()> {
        let mut tracking_config_map = Self::tracking_config_map()?;
        let mut tracking_map = SendableMap::from(Self::tracking_map()?);
        let tracking_fd = tracking_map.get().fd();

        // Register the tracking hook to all probes.
        probes.register_kernel_hook(
            Hook::from(tracking_hook::DATA)
                .reuse_map("tracking_config_map", tracking_config_map.fd())?
                .reuse_map("tracking_map", tracking_fd)?
                .to_owned(),
        )?;

        // For tracking skbs we only need the following two functions. First
        // track free events.
        let symbol = Symbol::from_name("skb_free_head")?;
        let key = symbol.addr()?.to_ne_bytes();
        let cfg = TrackingConfig {
            free: 1,
            inv_head: 0,
        };
        let cfg = unsafe { plain::as_bytes(&cfg) };
        tracking_config_map.update(&key, cfg, libbpf_rs::MapFlags::NO_EXIST)?;
        probes.add_probe(Probe::kprobe(symbol)?)?;

        // Then track invalidation head events.
        let symbol = Symbol::from_name("pskb_expand_head")?;
        let key = symbol.addr()?.to_ne_bytes();
        let cfg = TrackingConfig {
            free: 0,
            inv_head: 1,
        };
        let cfg = unsafe { plain::as_bytes(&cfg) };
        tracking_config_map.update(&key, cfg, libbpf_rs::MapFlags::NO_EXIST)?;
        probes.add_probe(Probe::kprobe(symbol)?)?;

        // Take care of gargabe collection of tracking info. This should be done
        // in the BPF part for most if not all skbs but we might lose some
        // information (and tracked functions might fail resulting in incorrect
        // information).
        self.garbage_collector = Some(thread::spawn(move || {
            let tracking_map = tracking_map.get_mut();

            loop {
                // Let's run every SKB_TRACKING_GC_INTERVAL seconds.
                thread::sleep(Duration::from_secs(SKB_TRACKING_GC_INTERVAL));
                let now =
                    Duration::from(time::clock_gettime(time::ClockId::CLOCK_MONOTONIC).unwrap());

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
        }));

        Ok(())
    }
}

// Please keep in sync with its BPF counterpart in bpf/tracking_hook.ebpf.c
#[repr(C)]
struct TrackingConfig {
    free: u8,
    inv_head: u8,
}

unsafe impl Plain for TrackingConfig {}

// Please keep in sync with its BPF counterpart in bpf/tracking_hook.ebpf.c
#[derive(Default)]
#[repr(C)]
struct TrackingInfo {
    timestamp: u64,
    last_seen: u64,
    orig_head: u64,
}

unsafe impl Plain for TrackingInfo {}
