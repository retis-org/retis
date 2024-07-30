use std::io::Write;

use anyhow::Result;

use super::series::EventSeries;
use crate::events::*;

pub(crate) enum PrintSingleFormat {
    Text(DisplayFormat),
    Json,
}

/// Handles event individually and write to a `Write`.
pub(crate) struct PrintSingle {
    writer: Box<dyn Write>,
    format: PrintSingleFormat,
}

impl PrintSingle {
    pub(crate) fn new(writer: Box<dyn Write>, format: PrintSingleFormat) -> Self {
        Self { writer, format }
    }

    /// Process events one by one (format & print).
    pub(crate) fn process_one(&mut self, e: &Event) -> Result<()> {
        match self.format {
            PrintSingleFormat::Text(ref mut format) => {
                if let Some(common) = e.get_section::<CommonEventMd>(SectionId::MdCommon) {
                    format.set_monotonic_offset(common.clock_monotonic_offset);
                }

                let mut event = format!("{}", e.display(format, &FormatterConf::new()));
                if !event.is_empty() {
                    match format.flavor {
                        DisplayFormatFlavor::SingleLine => event.push('\n'),
                        DisplayFormatFlavor::MultiLine => event.push_str("\n\n"),
                    }
                    self.writer.write_all(event.as_bytes())?;
                }
            }
            PrintSingleFormat::Json => {
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
    format: PrintSingleFormat,
}

impl PrintSeries {
    pub(crate) fn new(writer: Box<dyn Write>, format: PrintSingleFormat) -> Self {
        Self { writer, format }
    }

    /// Process events one by one (format & print).
    pub(crate) fn process_one(&mut self, series: &EventSeries) -> Result<()> {
        let mut content = String::new();
        match self.format {
            PrintSingleFormat::Text(ref mut format) => {
                let mut fconf = FormatterConf::new();
                let mut first = true;

                for event in series.events.iter() {
                    if let Some(common) = event.get_section::<CommonEventMd>(SectionId::MdCommon) {
                        format.set_monotonic_offset(common.clock_monotonic_offset);
                    }

                    content.push_str(&format!("{}", event.display(format, &fconf)));
                    if !content.is_empty() {
                        content.push('\n');
                        if first {
                            first = false;
                            fconf.inc_level(4);
                            fconf.set_item(Some('+'));
                        }
                    }
                }

                if !content.is_empty() {
                    content.push('\n');
                    self.writer.write_all(content.as_bytes())?;
                }
            }
            PrintSingleFormat::Json => {
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
