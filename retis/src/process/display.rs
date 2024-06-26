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

                let event = format!("{}", e.display(format));
                if !event.is_empty() {
                    self.writer.write_all(event.as_bytes())?;
                    match format.flavor {
                        DisplayFormatFlavor::SingleLine => self.writer.write_all(b"\n")?,
                        DisplayFormatFlavor::MultiLine => self.writer.write_all(b"\n\n")?,
                    }
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

    fn indent(n_spaces: usize, lines: String) -> String {
        if n_spaces == 0 || lines.is_empty() {
            return lines;
        }

        let mut res = Vec::new();
        let mut delim = "+ ";
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
            PrintSingleFormat::Text(ref mut format) => {
                let mut indent = 0;
                for event in series.events.iter() {
                    if let Some(common) = event.get_section::<CommonEventMd>(SectionId::MdCommon) {
                        format.set_monotonic_offset(common.clock_monotonic_offset);
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
