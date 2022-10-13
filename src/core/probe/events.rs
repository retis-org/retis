//! # Events
//!
//! Handle events reported by the Linux kernel probes. A ring buffer is used to
//! convey events from kernel probes to userspace. This was preferred over
//! perfbuf as it presents many advantages leading to better performances. To
//! further improve performances per-CPU ring buffers can be used, this might be
//! an improvement for later. See https://nakryiko.com/posts/bpf-ringbuf/ and
//! tools/testing/selftests/bpf/progs/test_ringbuf_multi.c (in the kernel source
//! tree).

use anyhow::Result;
use plain::Plain;
use std::{mem, time::Duration};

const EVENTS_MAX: u32 = 512;

/// Representation of events coming from the probes. It must match its eBPF
/// counterpart defined in src/core/probe/type/bpf/events.h. We're not using the
/// libbpf_rs skeleton to derive the C struct to its Rust counterpart as the
/// events handling here works w/o loading an eBPF object.
#[repr(C)]
#[derive(Default)]
struct Event {
    /// Probe symbol address, used to uniquely identify where an event comes
    /// from; can also be used to output the probe name thanks to
    /// /proc/kallsyms.
    ksym: u64,
    /// Timestamp of the event. It is set early by kernel probes.
    timestamp: u64,

    skb_etype: u16,
    rsvd: [u8; 14],
}
unsafe impl Plain for Event {}

/// Main structure representing the events handling in the crate. Sets up the
/// events map used by probes, implements the logic to retrieve and process
/// events.
pub(super) struct Events<'a> {
    /// eBPF map fd so it can be provided to probes to be reused.
    map_fd: i32,
    /// Ring buffer used for kernel<>us communication, for reporting events from
    /// the kernel.
    ring_buffer: libbpf_rs::RingBuffer<'a>,
}

impl<'a> Events<'a> {
    pub(super) fn new() -> Result<Events<'a>> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        // Map definition. Must be kept in sync with its eBPF counterpart in
        // bpf/events.h.
        let map = libbpf_rs::Map::create(
            libbpf_rs::MapType::RingBuf,
            Some("event_map"),
            0,
            0,
            mem::size_of::<Event>() as u32 * EVENTS_MAX,
            &opts,
        )
        .expect("Failed to create event map");

        let mut rb = libbpf_rs::RingBufferBuilder::new();
        rb.add(&map, process_event)?;
        let rb = rb.build()?;

        Ok(Events {
            map_fd: map.fd(),
            ring_buffer: rb,
        })
    }

    pub(super) fn fd(&self) -> i32 {
        self.map_fd
    }

    /// Polling loop for events coming from the ring buffer.
    pub(super) fn events_loop(&self) {
        loop {
            self.ring_buffer.poll(Duration::from_millis(10)).unwrap();
        }
    }
}

/// Get a raw event data from the buffer, coming from kernel probes. Parse &
/// process it.
fn process_event(data: &[u8]) -> i32 {
    let mut event = Event::default();
    plain::copy_from_bytes(&mut event, data).unwrap();

    // Dummy processing for now.
    println!(
        "{} {:#x} {:#x}",
        event.timestamp, event.ksym, event.skb_etype
    );
    0
}
