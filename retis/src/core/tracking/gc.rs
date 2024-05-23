//! # Tracking garbage collector
//!
//! When modules track packets or other structures using ebpf maps,
//! loosing events might some enties stale.
//!
//! This module provides a utility object that can take care of removeing
//! stale entries

use std::{collections::HashMap, ops::Fn, sync::Arc, thread, time::Duration};

use anyhow::{anyhow, Result};
use log::{error, warn};
use nix::time;

use crate::helpers::signals::Running;

pub(crate) struct TrackingGC {
    // Maps to track
    maps: Option<HashMap<String, libbpf_rs::MapHandle>>,
    // Duration extraction function. Based on the value of the map, it returns
    // the duration of the entry.
    extract_age: Arc<dyn Fn(Vec<u8>) -> Result<Duration> + Send + Sync + 'static>,
    // Interval of GC runs
    interval: u64,
    // Maximum age of entries. Older entires will be removed
    limit: u64,
    // The name of the thread
    name: String,

    thread: Option<thread::JoinHandle<()>>,
}

impl TrackingGC {
    // 60 seconds
    const DEFAULT_OLD_LIMIT: u64 = 60;
    // 5 seconds
    const DEFAULT_INTERVAL: u64 = 5;

    pub(crate) fn new<F>(
        name: &'static str,
        mut maps: HashMap<&'static str, libbpf_rs::MapHandle>,
        extract_age: F,
    ) -> Self
    where
        F: Fn(Vec<u8>) -> Result<Duration> + Send + Sync + 'static,
    {
        TrackingGC {
            maps: Some(maps.drain().map(|(n, m)| (n.to_string(), m)).collect()),
            extract_age: Arc::new(extract_age),
            interval: Self::DEFAULT_INTERVAL,
            limit: Self::DEFAULT_OLD_LIMIT,
            name: name.to_string(),
            thread: None,
        }
    }

    pub(crate) fn interval(mut self, interval: u64) -> Self {
        self.interval = interval;
        self
    }

    pub(crate) fn limit(mut self, limit: u64) -> Self {
        self.limit = limit;
        self
    }

    pub(crate) fn start(&mut self, state: Running) -> Result<()> {
        let interval = self.interval;
        let limit = self.limit;
        let mut maps = self.maps.take().unwrap();
        let extract_age = self.extract_age.clone();
        self.thread = Some(thread::Builder::new().name(self.name.clone()).spawn(move || {
            let running = || -> bool {
                // Let's run every interval seconds.
                for _ in 0..interval {
                    thread::sleep(Duration::from_secs(1));
                    if !state.running() {
                        return false;
                    }
                }
                true
            };

            while running() {
                let now = Duration::from(time::clock_gettime(time::ClockId::CLOCK_MONOTONIC).unwrap());

                // Loop through the tracking map entries and see if we see old
                // ones we should remove manually.
                for (name, map) in maps.iter_mut() {
                    let mut to_remove = Vec::new();
                    for key in map.keys() {
                        if let Ok(Some(raw)) = map.lookup(&key, libbpf_rs::MapFlags::ANY) {
                            // Get the Duration associated with the entry.
                            let age = match (extract_age)(raw) {
                                Ok(age) => age,
                                Err(e) => {
                                    error!("{name}: entry age extraction failed for key {}: {e}", Self::format_key(map, key));
                                    continue;
                                }
                            };
                            if now.saturating_sub(age)
                                > Duration::from_secs(limit)
                            {
                                to_remove.push(key);
                            }
                        }
                    }
                    // Actually remove the outdated entries and issue a warning as
                    // while it can be expected, it should not happen too often.
                    for key in to_remove {
                        map.delete(&key).ok();
                        warn!("Removed old entry from {name} tracking map: {}", Self::format_key(map, key));
                    }
                }
            }
        })?);
        Ok(())
    }

    pub(crate) fn join(&mut self) -> Result<()> {
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|e| anyhow!("Failed to join thread {}: {e:?}", self.name))
        } else {
            Ok(())
        }
    }

    pub(crate) fn format_key(map: &libbpf_rs::MapHandle, key: Vec<u8>) -> String {
        let default_format = || format!("{:#x?}", key);

        // Try to format the key as unsigned integers and fall back to printing the u8 vector as
        // hex if we fail.
        match map.key_size() {
            4 => {
                let bytes: Result<[u8; 4], _> = key[..4].try_into();
                match bytes {
                    Ok(bytes) => format!("{}", u32::from_ne_bytes(bytes)),
                    Err(_) => default_format(),
                }
            }
            8 => {
                let bytes: Result<[u8; 8], _> = key[..8].try_into();
                match bytes {
                    Ok(bytes) => format!("{}", u64::from_ne_bytes(bytes)),
                    Err(_) => default_format(),
                }
            }
            _ => default_format(),
        }
    }
}
