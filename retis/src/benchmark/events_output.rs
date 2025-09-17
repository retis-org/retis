use std::{fs::OpenOptions, time::Instant};

use anyhow::{bail, Result};

use crate::{
    events::{file::FileEventsFactory, *},
    process::{display::*, series::EventSorter, tracking::AddTracking},
};

/// Benchmark time to output events (text, json).
pub(super) fn bench(ci: bool) -> Result<()> {
    let iters = match ci {
        false => 1000000,
        true => 1,
    };

    // PrintEvent benchmark

    let mut factory = FileEventsFactory::from_path("retis/test_data/test_events_bench.json")?;
    let event = match factory.next_event()? {
        Some(event) => event,
        _ => bail!("Could not get event from test file"),
    };

    let mut p = PrintEvent::new(
        Box::new(OpenOptions::new().write(true).open("/dev/null")?),
        PrintEventFormat::Text(DisplayFormat::new()),
    );
    let now = Instant::now();
    for _ in 0..iters {
        p.process_one(&event)?;
    }
    println!(
        "1M_print_single_singleline_us {}",
        now.elapsed().as_micros()
    );

    let mut p = PrintEvent::new(
        Box::new(OpenOptions::new().write(true).open("/dev/null")?),
        PrintEventFormat::Text(DisplayFormat::new().multiline(true)),
    );
    let now = Instant::now();
    for _ in 0..iters {
        p.process_one(&event)?;
    }
    println!("1M_print_single_multiline_us {}", now.elapsed().as_micros());

    let mut p = PrintEvent::new(
        Box::new(OpenOptions::new().write(true).open("/dev/null")?),
        PrintEventFormat::Json,
    );
    let now = Instant::now();
    for _ in 0..iters {
        p.process_one(&event)?;
    }
    println!("1M_print_single_json_us {}", now.elapsed().as_micros());

    // PrintSeries benchmark

    let mut factory = FileEventsFactory::from_path("retis/test_data/test_events_bench.json")?;
    let mut tracker = AddTracking::new();
    let mut series = EventSorter::new();

    while let Some(mut event) = factory.next_event()? {
        tracker.process_one(&mut event)?;
        series.add(event);
    }
    let series = series.pop_oldest()?.unwrap();

    let mut p = PrintSeries::new(
        Box::new(OpenOptions::new().write(true).open("/dev/null")?),
        PrintEventFormat::Text(DisplayFormat::new()),
    );
    let now = Instant::now();
    for _ in 0..iters {
        p.process_one(&series)?;
    }
    println!(
        "1M_print_series_singleline_us {}",
        now.elapsed().as_micros()
    );

    let mut p = PrintSeries::new(
        Box::new(OpenOptions::new().write(true).open("/dev/null")?),
        PrintEventFormat::Text(DisplayFormat::new().multiline(true)),
    );
    let now = Instant::now();
    for _ in 0..iters {
        p.process_one(&series)?;
    }
    println!("1M_print_series_multiline_us {}", now.elapsed().as_micros());

    let mut p = PrintSeries::new(
        Box::new(OpenOptions::new().write(true).open("/dev/null")?),
        PrintEventFormat::Json,
    );
    let now = Instant::now();
    for _ in 0..iters {
        p.process_one(&series)?;
    }
    println!("1M_print_series_json_us {}", now.elapsed().as_micros());

    Ok(())
}
