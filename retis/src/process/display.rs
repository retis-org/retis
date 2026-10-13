use std::{
    io::Write,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{anyhow, Result};
use log::error;

use crate::{events::*, helpers::signals::*};

/// Select the format to follow when printing events with `EventFormatter`.
pub(crate) enum EventFormat {
    /// Text(format): display the events in a text representation following the
    /// rules defined in `format` (see `DisplayFormat`).
    Text(DisplayFormat),
    /// Json: display the event as JSON.
    Json,
}

/// The return value of EventFormatter::next()
pub(crate) enum EventResult {
    /// The Factory was able to create a new event.
    Event(Vec<u8>),
    /// The timeout went off but a new attempt to retrieve an event might succeed.
    Timeout,
}

/// Handles event individually and format them according to the settings.
#[derive(Clone)]
pub(crate) struct EventFormatter {
    run: Running,
    format: Arc<RwLock<EventFormat>>,
    txc: crossbeam_channel::Sender<Vec<u8>>,
    rxc: crossbeam_channel::Receiver<Vec<u8>>,
}

impl EventFormatter {
    pub(crate) fn new(run: Running, threads: usize, format: EventFormat) -> Self {
        let (txc, rxc) = crossbeam_channel::bounded(threads * 2);
        Self {
            run,
            format: Arc::new(RwLock::new(format)),
            txc,
            rxc,
        }
    }

    /// Process events one by one.
    pub(crate) fn process_event(&self, e: &Event) -> Result<()> {
        if let Some(startup) = &e.startup {
            // As this only happens if a startup section is seen, take a write
            // lock regardless of the underlying format.
            if let EventFormat::Text(ref mut format) = *self.format.write().unwrap() {
                format.monotonic_offset = Some(startup.clock_monotonic_offset);
            }
        }

        let event = match *self.format.read().unwrap() {
            EventFormat::Text(format) => {
                let mut event = format!("{}", e.display(&format, &FormatterConf::new()));
                if !event.is_empty() {
                    event.push('\n');
                    if format.multiline {
                        event.push('\n');
                    }
                }

                event.as_bytes().to_vec()
            }
            EventFormat::Json => {
                let mut event = serde_json::to_vec(&e)?;
                event.push(b'\n');
                event
            }
        };

        if let Err(e) = channel_send(&self.txc, &self.run, event) {
            error!("Could not send formatted event: {e}");
        }

        Ok(())
    }

    /// Get the next formatted event, as bytes.
    pub(crate) fn next(&self, timeout: Duration) -> Result<EventResult> {
        match self.rxc.recv_timeout(timeout) {
            Ok(event) => Ok(EventResult::Event(event)),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => Ok(EventResult::Timeout),
            Err(e) => Err(anyhow!(format!("{e}"))),
        }
    }
}

/// Handles event series formatting and writing to a `Write`.
pub(crate) struct PrintSeries {
    writer: Box<dyn Write>,
    format: EventFormat,
}

impl PrintSeries {
    pub(crate) fn new(writer: Box<dyn Write>, format: EventFormat) -> Self {
        Self { writer, format }
    }

    /// Process events one by one (format & print).
    pub(crate) fn process_one(&mut self, series: &EventSeries) -> Result<()> {
        let mut content = String::new();
        match self.format {
            EventFormat::Text(ref mut format) => {
                let mut fconf = FormatterConf::new();
                let mut first = true;

                for event in series.events.iter() {
                    if let Some(startup) = &event.startup {
                        format.monotonic_offset = Some(startup.clock_monotonic_offset);
                    }

                    content.push_str(&format!("{}", event.display(format, &fconf)));
                    if !content.is_empty() {
                        content.push('\n');
                        if first {
                            first = false;
                            fconf.inc_level(4);
                            fconf.set_item(Some('↳'));
                        }
                    }
                }

                if !content.is_empty() {
                    content.push('\n');

                    self.writer.write_all(content.as_bytes())?;
                }
            }
            EventFormat::Json => {
                let mut event = serde_json::to_vec(&series)?;
                event.push(b'\n');
                self.writer.write_all(&event)?;
            }
        }

        Ok(())
    }

    /// Flush underlying writers.
    pub(crate) fn flush(&mut self) -> Result<()> {
        Ok(self.writer.flush()?)
    }
}
