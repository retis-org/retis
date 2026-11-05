//! Common logic to handle and output events and series from an input file. This
//! is used in both the print and sort commands.

use std::io::{self, ErrorKind};

use anyhow::Result;
use clap::Args;

use super::{display::*, series::EventSorter, tracking::*};
use crate::{
    cli::CliDisplayFormat,
    events::{file::*, *},
    helpers::{file_rotate::InputDataFile, signals::*},
};

// Common arguments used for commands printing an input event files.
#[derive(Args, Debug, Default)]
pub(super) struct PrintArgs {
    #[arg(help = InputDataFile::help())]
    pub(super) input: Option<InputDataFile>,
    #[arg(long, help = "Format used when printing an event")]
    #[clap(value_enum, default_value_t=CliDisplayFormat::MultiLine)]
    pub(super) format: CliDisplayFormat,
    #[arg(
        long,
        default_value_t = 1000,
        help = "Maximum number of events to buffer while processing the input file.

Sorting events requires storing events in a buffer while we wait to see if there is any other event th
at belongs to the same series. If there are many interleaved events, you may need to increase the size
 of the buffer to properly sort all events.

A value of zero means the buffer can grow endlessly."
    )]
    pub(super) max_buffer: usize,
    #[arg(long, help = "Print the time as UTC")]
    pub(super) utc: bool,
    #[arg(short = 'e', help = "Print link-layer information from the packet")]
    pub(super) print_ll: bool,
}

// Parses `PrintArgs` and issue a `DisplayFormat`, to be used in printers.
pub(super) fn get_print_format(args: &PrintArgs) -> DisplayFormat {
    DisplayFormat::new()
        .multiline(args.format == CliDisplayFormat::MultiLine)
        .time_format(if args.utc {
            TimeFormat::UtcDate
        } else {
            TimeFormat::MonotonicTimestamp
        })
        .print_ll(args.print_ll)
}

// Handles all the logic to sort and print events from an input file. If
// `add_tracking` is true the `TrackingInfo` event section is added while
// processing the events, which triggers sorting them into series.
pub(super) fn do_print(
    args: &PrintArgs,
    run: Running,
    mut printers: Vec<PrintSeries>,
    add_tracking: bool,
) -> Result<()> {
    // Get the event factory and output format from the args.
    let factory = args.input.clone().unwrap_or_default().to_factory()?;
    match factory.file_type() {
        FileType::Event => {
            do_print_events(run, factory, &mut printers, args.max_buffer, add_tracking)?
        }
        FileType::Series => do_print_series(run, factory, &mut printers)?,
    }

    // Flush printers before exiting.
    printers.iter_mut().try_for_each(|p| p.flush())
}

fn do_print_events(
    run: Running,
    mut factory: FileEventsFactory,
    printers: &mut [PrintSeries],
    max_buffer: usize,
    add_tracking: bool,
) -> Result<()> {
    // Regardless of if we group events into series, we need to sort events at
    // least by their timestamp as they could have been handled out of order at
    // collect time.
    let mut sorter = EventSorter::default();

    // Only add the tracking information if requested (triggers grouping events
    // into series).
    let mut tracker = if add_tracking {
        Some(AddTracking::default())
    } else {
        None
    };

    while run.running() {
        match factory.next_event()? {
            Some(mut event) => {
                if let Some(ref mut tracker) = tracker {
                    tracker.process_one(&mut event)?;
                }
                sorter.add(event);

                // We'll flush at exit time.
                if max_buffer == 0 {
                    continue;
                }

                // Flush the latest events / series, if needed.
                while sorter.len() >= max_buffer {
                    sorter
                        .pop()
                        .drain(..)
                        .try_for_each(|series| output_series(printers, series))?;
                }
            }
            None => break,
        }
    }

    // Flush all the events before exiting.
    while sorter.len() > 0 {
        sorter
            .pop()
            .drain(..)
            .try_for_each(|series| output_series(printers, series))?;
    }

    Ok(())
}

fn do_print_series(
    run: Running,
    mut factory: FileEventsFactory,
    printers: &mut [PrintSeries],
) -> Result<()> {
    while run.running() {
        match factory.next_series()? {
            Some(series) => output_series(printers, series)?,
            None => break,
        }
    }

    Ok(())
}

fn output_series(printers: &mut [PrintSeries], series: EventSeries) -> Result<()> {
    for p in printers.iter_mut() {
        if let Err(e) = p.process_one(&series) {
            match e.downcast_ref::<io::Error>() {
                Some(io_error) if io_error.kind() == ErrorKind::BrokenPipe => break,
                _ => return Err(e),
            }
        }
    }

    Ok(())
}
