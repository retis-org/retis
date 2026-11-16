use std::{
    slice,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use log::error;

use crate::{events::*, helpers::signals::*};

/// Item to output in a single batch, either a single event or a single series
/// of events.
enum OutputItem<'a> {
    Event(&'a Event),
    Series(&'a EventSeries),
}

impl OutputItem<'_> {
    pub fn iter(&self) -> slice::Iter<'_, Event> {
        match self {
            Self::Event(event) => slice::from_ref(*event).iter(),
            Self::Series(series) => series.events.iter(),
        }
    }
}

impl<'a> From<&'a Event> for OutputItem<'a> {
    fn from(event: &'a Event) -> Self {
        Self::Event(event)
    }
}

impl<'a> From<&'a EventSeries> for OutputItem<'a> {
    fn from(series: &'a EventSeries) -> Self {
        Self::Series(series)
    }
}

/// Select the format to follow when printing events.
pub(crate) enum EventFormat {
    /// Text(format): display the events in a text representation following the
    /// rules defined in `format` (see `DisplayFormat`).
    Text(DisplayFormat),
    /// Json: display the event as JSON.
    Json,
}

/// Handles item formatting. The result is available on the exposed receive
/// channel.
#[derive(Clone)]
pub(crate) struct ItemFormatter {
    format: Arc<RwLock<EventFormat>>,
    run: Running,
    txc: crossbeam_channel::Sender<Vec<u8>>,
    pub(crate) rxc: crossbeam_channel::Receiver<Vec<u8>>,
}

impl ItemFormatter {
    pub(crate) fn new(format: EventFormat, threads: usize, run: Running) -> Self {
        let (txc, rxc) = crossbeam_channel::bounded(threads * 2);
        Self {
            format: Arc::new(RwLock::new(format)),
            run,
            txc,
            rxc,
        }
    }

    /// Process events one by one (format & print).
    #[allow(private_bounds)]
    pub(crate) fn process_one<'a, T: Into<OutputItem<'a>>>(&self, item: T) -> Result<()> {
        let item = item.into();
        let mut output = Vec::new();

        // Look for clock offsets. As this is a rare event, take a write lock
        // regardless of the underlying format.
        item.iter().for_each(|e| {
            if let Some(startup) = &e.startup {
                if let EventFormat::Text(ref mut format) = *self.format.write().unwrap() {
                    format.monotonic_offset = Some(startup.clock_monotonic_offset);
                }
            }
        });

        match *self.format.read().unwrap() {
            EventFormat::Text(format) => {
                let mut fconf = FormatterConf::new();
                let mut first = true;

                for event in item.iter() {
                    let mut event = format!("{}", event.display(&format, &fconf));
                    if !event.is_empty() && first {
                        first = false;
                        fconf.inc_level(4);
                        fconf.set_item(Some('↳'));
                    }

                    if !event.is_empty() {
                        event.push('\n');
                        output.extend(event.as_bytes());
                    }
                }
                output.push(b'\n');
            }
            EventFormat::Json => {
                output = match item {
                    OutputItem::Event(event) => serde_json::to_vec(&event)?,
                    OutputItem::Series(series) => serde_json::to_vec(&series)?,
                };
                output.push(b'\n');
            }
        }

        if let Err(e) = channel_send(&self.txc, &self.run, output) {
            error!("Could not send formatted event: {e}");
        }

        Ok(())
    }
}
