//! # Capinfo
//!
//! Capinfo is a post-processing command that prints information about a retis capture.

use std::{collections::HashMap, path::PathBuf};

use anyhow::Result;
use clap::Parser;

use crate::{
    cli::*,
    events::{
        file::{FileEventsFactory, FileType},
        *,
    },
    helpers::signals::Running,
};

#[derive(Parser, Debug, Default)]
#[command(name = "capinfo", about = "Print information about a retis capture.")]
pub(crate) struct Capinfo{
    /// File from which to read events.
    #[arg(default_value = "retis.data")]
    pub(super) input: PathBuf,
}

impl SubCommandParserRunner for Capinfo {
    fn run(&mut self, _: &MainConfig) -> Result<()> {
        let mut stats = EventCapInfo::new();

        let run = Running::new();
        run.register_term_signals()?;

        let mut factory = FileEventsFactory::new(self.input.as_path())?;

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

#[derive(Default)]
struct EventCapInfo {
    probes: HashMap<String, u32>,
    n_events: u64,
    n_series: u64,
}

impl EventCapInfo {
    fn new() -> Self {
        Self::default()
    }

    fn process_series(&mut self, series: &EventSeries) -> Result<()> {
        self.n_series += 1;
        for event in series.events.iter() {
            self.process_event(event)?;
        }
        Ok(())
    }

    fn process_event(&mut self, event: &Event) -> Result<()> {
        let probe_name = if let Some(kernel) = &event.kernel {
            Some(format!("{}/{}", kernel.probe_type, kernel.symbol))
        } else {
            event
                .userspace
                .as_ref()
                .map(|user| format!("{}/{}", user.probe_type, user.symbol))
        };
        if let Some(probe_name) = probe_name {
            let stat = self.probes.entry(probe_name).or_insert(0);
            *stat += 1;
        }
        self.n_events += 1;
        Ok(())
    }

    fn print(&self) -> Result<()> {
        if self.n_series > 0 {
            println!("Number of series: {}", self.n_series);
        }
        println!("Number of events: {}", self.n_events);
        println!("Probes:");
        let mut sorted = self.probes.keys().collect::<Vec<&String>>();
        sorted.sort();
        for probe in sorted {
            println!("  {}: {}", probe, self.probes.get(probe).unwrap());
        }
        Ok(())
    }
}
