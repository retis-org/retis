//! Common logic to handle and output events and series from an input file. This
//! is used in both the print and sort commands.

use std::{io::ErrorKind, thread, time::Duration};

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

Sorting events requires storing events in a buffer while we wait to see if there is any other event that belongs to the same series. If there are many interleaved events, you may need to increase the size of the buffer to properly sort all events.

A value of zero means the buffer can grow endlessly."
    )]
    pub(super) max_buffer: usize,
    #[arg(long, help = "Print the time as UTC")]
    pub(super) utc: bool,
    #[arg(short = 'e', help = "Print link-layer information from the packet")]
    pub(super) print_ll: bool,
}

impl PrintArgs {
    // Parses `PrintArgs` and issue a `DisplayFormat`, to be used in printers.
    pub(super) fn get_print_format(&self) -> DisplayFormat {
        DisplayFormat::new()
            .multiline(self.format == CliDisplayFormat::MultiLine)
            .time_format(if self.utc {
                TimeFormat::UtcDate
            } else {
                TimeFormat::MonotonicTimestamp
            })
            .print_ll(self.print_ll)
    }
}

// Handles all the logic to sort and print events from an input file. If
// `add_tracking` is true the `TrackingInfo` event section is added while
// processing the events, which triggers sorting them into series.
pub(super) fn do_print(
    args: &PrintArgs,
    run: Running,
    mut pipes: Vec<ItemDisplayPipe>,
    add_tracking: bool,
) -> Result<()> {
    // Get the event factory and output format from the args.
    let factory = args.input.clone().unwrap_or_default().to_factory()?;

    let max_buffer = args.max_buffer;
    let mut formatters_tx = pipes
        .iter()
        .map(|p| p.formatter().clone())
        .collect::<Vec<_>>();
    let run_tx = run.clone();

    let thread = thread::Builder::new().name("retis-print".to_string());
    thread.spawn(move || -> Result<()> {
        match factory.file_type() {
            FileType::Event => do_format_events(
                run_tx.clone(),
                factory,
                &mut formatters_tx,
                max_buffer,
                add_tracking,
            )?,
            FileType::Series => do_format_series(run_tx.clone(), factory, &mut formatters_tx)?,
        }
        run_tx.terminate();
        Ok(())
    })?;

    write_pipes(&mut pipes, Some(&run), None, None)?;

    // Dequeue pending events and flush writers before exiting.
    while write_pipes(&mut pipes, None, None, Some(10))? > 0 {}
    pipes.iter_mut().try_for_each(|p| p.writer_mut().flush())?;

    Ok(())
}

fn do_format_events(
    run: Running,
    mut factory: FileEventsFactory,
    formatters: &mut [ItemFormatter],
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
                    sorter.pop().drain(..).try_for_each(|series| {
                        formatters
                            .iter_mut()
                            .try_for_each(|f| f.process_one(&series))
                    })?;
                }
            }
            None => break,
        }
    }

    // Flush all the events before exiting.
    while sorter.len() > 0 {
        sorter.pop().drain(..).try_for_each(|series| {
            formatters
                .iter_mut()
                .try_for_each(|f| f.process_one(&series))
        })?;
    }

    Ok(())
}

fn do_format_series(
    run: Running,
    mut factory: FileEventsFactory,
    formatters: &mut [ItemFormatter],
) -> Result<()> {
    while run.running() {
        match factory.next_series()? {
            Some(series) => formatters
                .iter_mut()
                .try_for_each(|f| f.process_one(&series))?,
            None => break,
        }
    }

    Ok(())
}

pub(crate) fn write_pipes(
    pipes: &mut Vec<ItemDisplayPipe>,
    run: Option<&Running>,
    budget: Option<usize>,
    timeout_ms: Option<u64>,
) -> Result<usize> {
    let mut i = 0;
    while run.is_some_and(|run| run.running())
        && !pipes.is_empty()
        && (budget.is_some_and(|b| b - i > 0) || budget.is_none())
    {
        let mut sel = crossbeam_channel::Select::new();
        pipes.iter().for_each(|p| _ = sel.recv(&p.formatter().rxc));

        let op = match sel
            .select_timeout(Duration::from_millis(timeout_ms.unwrap_or(CALL_TIMEOUT_MS)))
        {
            Ok(op) => op,
            Err(crossbeam_channel::SelectTimeoutError) => return Ok(i),
        };
        let index = op.index();

        if let Ok(event) = op.recv(&pipes[index].formatter().rxc) {
            match pipes[index].writer_mut().write_all(&event) {
                Err(e) if e.kind() == ErrorKind::BrokenPipe => _ = pipes.remove(index),
                Err(e) => return Err(e.into()),
                _ => i += 1,
            }
        }
    }
    Ok(i)
}
