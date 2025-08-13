use std::time::Instant;

use anyhow::Result;

use super::helpers::build_raw_event;
use crate::{collect::collector::section_factories, core::events::*};

/// Benchmark time to parse a bunch of raw events.
pub(super) fn bench(ci: bool) -> Result<()> {
    let iters = match ci {
        false => 1000000,
        true => 1,
    };

    let mut factories = section_factories()?;

    // Build a raw event for later consumption by factories.
    let data = build_raw_event()?;

    let now = Instant::now();
    for _ in 0..iters {
        parse_raw_event(&data, &mut factories)?;
    }
    println!("1M_raw_events_parsing_us {}", now.elapsed().as_micros());

    Ok(())
}
