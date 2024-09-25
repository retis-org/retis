use std::io::Write;

use anyhow::Result;

use super::series::EventSeries;
use crate::events::*;

/// Select the format to follow when printing events with `PrintEvent`.
pub(crate) enum PrintEventFormat {
    /// Text(format): display the events in a text representation following the
    /// rules defined in `format` (see `DisplayFormat`).
    Text(DisplayFormat),
    /// Json: display the event as JSON.
    Json,
}

/// Handles event individually and write to a `Write`.
pub(crate) struct PrintEvent {
    writer: Box<dyn Write>,
    format: PrintEventFormat,
}

impl PrintEvent {
    pub(crate) fn new(writer: Box<dyn Write>, format: PrintEventFormat) -> Self {
        Self { writer, format }
    }

    /// Process events one by one (format & print).
    pub(crate) fn process_one(&mut self, e: &Event) -> Result<()> {
        match self.format {
            PrintEventFormat::Text(ref mut format) => {
                if let Some(common) = e.get_section::<StartupEvent>(SectionId::Startup) {
                    format.monotonic_offset = Some(common.clock_monotonic_offset);
                }

                let event = format!("{}", e.display(format));
                if !event.is_empty() {
                    self.writer.write_all(event.as_bytes())?;
                    self.writer
                        .write_all(if format.multiline { b"\n\n" } else { b"\n" })?;
                }
            }
            PrintEventFormat::Json => {
                let mut event = serde_json::to_vec(&e.to_json())?;
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

/// Handles event series formatting and writing to a `Write`.
pub(crate) struct PrintSeries {
    writer: Box<dyn Write>,
    format: PrintEventFormat,
}

impl PrintSeries {
    pub(crate) fn new(writer: Box<dyn Write>, format: PrintEventFormat) -> Self {
        Self { writer, format }
    }

    fn indent(n_spaces: usize, lines: String) -> String {
        if n_spaces == 0 || lines.is_empty() {
            return lines;
        }

        let mut res = Vec::new();
        let mut delim = "↳ ";
        for line in lines.split('\n') {
            res.push(format!("{}{}{}", " ".repeat(n_spaces), delim, line));
            delim = "  ";
        }

        res.join("\n")
    }

    /// Process events one by one (format & print).
    pub(crate) fn process_one(&mut self, series: &EventSeries) -> Result<()> {
        let mut content = String::new();
        match self.format {
            PrintEventFormat::Text(ref mut format) => {
                let mut indent = 0;
                for event in series.events.iter() {
                    if let Some(common) = event.get_section::<StartupEvent>(SectionId::Startup) {
                        format.monotonic_offset = Some(common.clock_monotonic_offset);
                    }

                    content.push_str(&Self::indent(indent, format!("{}", event.display(format))));
                    if !content.is_empty() {
                        content.push('\n');
                        indent = 2;
                    }
                }

                if !content.is_empty() {
                    content.push('\n');
                    self.writer.write_all(content.as_bytes())?;
                }
            }
            PrintEventFormat::Json => {
                let mut event = serde_json::to_vec(&series.to_json())?;
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
