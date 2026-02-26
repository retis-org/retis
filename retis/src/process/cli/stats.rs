//! # Stats
//!
//! Stats is a post-processing command that prints information about a retis capture.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use clap::Parser;

use crate::{
    cli::*,
    events::{file::FileType, helpers::time::format_date_time, *},
    helpers::{file_rotate::InputDataFile, signals::Running},
};

#[derive(Parser, Debug, Default)]
#[command(name = "stats", about = "Print information about a capture.")]
pub(crate) struct Stats {
    #[arg(help = InputDataFile::help())]
    pub(super) input: Option<InputDataFile>,
}

impl SubCommandParserRunner for Stats {
    fn run(&mut self, _: &MainConfig) -> Result<()> {
        let mut stats = StatsProcessor::new();

        let run = Running::new();
        run.register_term_signals()?;

        // Create event factory.
        let mut factory = self.input.clone().unwrap_or_default().to_factory()?;

        match factory.file_type() {
            FileType::Event => {
                while run.running() {
                    match factory.next_event()? {
                        None => break,
                        Some(event) => stats.process_event(&event)?,
                    }
                }
            }
            FileType::Series => {
                while run.running() {
                    match factory.next_series()? {
                        Some(series) => stats.process_series(&series)?,
                        None => break,
                    }
                }
            }
        }
        stats.print()
    }
}

// Processes statistics of one or more files (if they were rotated)
#[derive(Default)]
struct StatsProcessor {
    files: Vec<FileStats>,
}

impl StatsProcessor {
    fn new() -> Self {
        Self::default()
    }

    fn process_series(&mut self, series: &EventSeries) -> Result<()> {
        if let Some(startup) = series.events.first().and_then(|e| e.startup.as_ref()) {
            // Currently, sorted files are not split, so we only keep one FileStats.
            if self.files.is_empty() {
                let new_file = FileStats::new(startup);
                self.files.push(new_file);
            }
            Ok(())
        } else {
            self.files
                .last_mut()
                .ok_or_else(|| anyhow!("missing startup event"))?
                .process_series(series)
        }
    }

    fn process_event(&mut self, event: &Event) -> Result<()> {
        if let Some(startup) = &event.startup {
            let new_file = FileStats::new(startup);
            self.files.push(new_file);
            Ok(())
        } else {
            self.files
                .last_mut()
                .ok_or_else(|| anyhow!("missing startup event"))?
                .process_event(event)
        }
    }

    fn print(&self) -> Result<()> {
        for file in self.files.iter() {
            file.print()?;
        }
        Ok(())
    }
}

// Processes statistics of a single file
struct FileStats {
    startup: StartupEvent,
    probes: HashMap<String, usize>,
    errors: HashMap<String, usize>,
    first_ts: Option<u64>,
    last_ts: Option<u64>,
    n_events: u64,
    n_series: u64,
}

impl FileStats {
    fn new(startup: &StartupEvent) -> Self {
        FileStats {
            startup: startup.clone(),
            probes: HashMap::default(),
            errors: HashMap::default(),
            first_ts: None,
            last_ts: None,
            n_events: 0,
            n_series: 0,
        }
    }

    fn process_series(&mut self, series: &EventSeries) -> Result<()> {
        if series.events.len() == 1 && series.events.get(1).is_some_and(|e| e.startup.is_some()) {
            // Skip sections that only contain startup events
            return Ok(());
        }
        self.n_series += 1;
        for event in series.events.iter() {
            self.process_event(event)?;
        }
        Ok(())
    }

    fn process_event(&mut self, event: &Event) -> Result<()> {
        if let Err(error) = self.do_process_event(event) {
            let error = error.to_string();
            let err_stat = self.errors.entry(error).or_insert(0);
            *err_stat += 1;
        }
        Ok(())
    }

    fn do_process_event(&mut self, event: &Event) -> Result<()> {
        if event.startup.is_some() {
            return Ok(());
        }

        let ts = if let Some(common) = &event.common {
            common.timestamp
        } else {
            bail!("Invalid event: no common section")
        };

        let probe_name = if let Some(kernel) = &event.kernel {
            format!("{}/{}", kernel.probe_type, kernel.symbol)
        } else if let Some(user) = &event.userspace {
            format!("{}/{}", user.probe_type, user.symbol)
        } else {
            bail!("Invalid event: no kernel or userspace section")
        };

        let stat = self.probes.entry(probe_name).or_insert(0);
        *stat += 1;

        self.first_ts.get_or_insert(ts);

        if self.last_ts.unwrap_or(0) < ts {
            self.last_ts = Some(ts)
        }
        self.n_events += 1;
        Ok(())
    }

    fn print_common(&self) {
        println!("Retis version: {}", self.startup.retis_version);
        println!("Retis cmdline: {}", self.startup.cmdline);
    }

    fn print(&self) -> Result<()> {
        if let Some(idx) = self.startup.split_file.as_ref().map(|s| s.id) {
            if idx == 0 {
                self.print_common();
            }
            println!("\nSplit index: {}", idx);
        } else {
            self.print_common();
        }
        if self.n_series > 0 {
            println!("Number of series: {}", self.n_series);
        }
        println!("Number of events: {}", self.n_events);
        if let Some(first_ts) = self.first_ts {
            println!(
                "First event at: {}",
                format_date_time(
                    TimeFormat::UtcDate,
                    first_ts,
                    Some(self.startup.clock_monotonic_offset)
                )
            );
        }
        if let Some(last_ts) = self.last_ts {
            println!(
                "Last event at: {}",
                format_date_time(
                    TimeFormat::UtcDate,
                    last_ts,
                    Some(self.startup.clock_monotonic_offset)
                )
            );
        }
        if !self.probes.is_empty() {
            println!("Probes:");
            let mut sorted: Vec<_> = self.probes.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            for (probe, num) in sorted {
                println!("  {}: {}", probe, num);
            }
        }
        if !self.errors.is_empty() {
            println!("Errors:");
            for (err, num) in self.errors.iter() {
                println!("  {}: {}", err, num);
            }
        }
        Ok(())
    }
}
