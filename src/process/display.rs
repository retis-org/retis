use std::io::Write;

use anyhow::Result;

use super::series::EventSeries;
use crate::events::*;

enum PrintSingleFormat {
    Text(DisplayFormat),
    Json,
}

/// Handles event individually and write to a `Write`.
pub(crate) struct PrintSingle {
    writer: Box<dyn Write>,
    format: PrintSingleFormat,
}

impl PrintSingle {
    pub(crate) fn text(writer: Box<dyn Write>, format: DisplayFormat) -> Self {
        Self {
            writer,
            format: PrintSingleFormat::Text(format),
        }
    }

    pub(crate) fn json(writer: Box<dyn Write>) -> Self {
        Self {
            writer,
            format: PrintSingleFormat::Json,
        }
    }

    /// Process events one by one (format & print).
    pub(crate) fn process_one(&mut self, e: &Event) -> Result<()> {
        match self.format {
            PrintSingleFormat::Text(format) => {
                let event = match format {
                    DisplayFormat::SingleLine => format!("{}\n", e.display(format)),
                    DisplayFormat::MultiLine => format!("\n{}\n", e.display(format)),
                };
                self.writer.write_all(event.as_bytes())?;
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
    pub(crate) fn text(writer: Box<dyn Write>, format: DisplayFormat) -> Self {
        Self {
            writer,
            format: PrintSingleFormat::Text(format),
        }
    }

    pub(crate) fn json(writer: Box<dyn Write>) -> Self {
        Self {
            writer,
            format: PrintSingleFormat::Json,
        }
    }

    fn indent(n_spaces: usize, lines: String) -> String {
        lines
            .split('\n')
            .map(|line| format!("{}{}", " ".repeat(n_spaces), line))
            .collect::<Vec<String>>()
            .join("\n")
    }

    /// Process events one by one (format & print).
    pub(crate) fn process_one(&mut self, series: &EventSeries) -> Result<()> {
        let mut content = String::new();
        match self.format {
            PrintSingleFormat::Text(format) => {
                match format {
                    DisplayFormat::SingleLine => {
                        if let Some(first) = series.events.first() {
                            content.push_str(&format!("\n{}\n", first.display(format)));
                        }
                        for event in series.events.iter().skip(1) {
                            content
                                .push_str(&Self::indent(2, format!("+ {}", event.display(format))));
                            content.push('\n');
                        }
                    }
                    DisplayFormat::MultiLine => {
                        if let Some(first) = series.events.first() {
                            content.push('\n');
                            content.push_str(&format!("{}", first.display(format)));
                            content.push('\n');
                        }
                        for event in series.events.iter().skip(1) {
                            content
                                .push_str(&Self::indent(2, format!("+ {}", event.display(format))));
                            content.push('\n');
                        }
                    }
                }
                self.writer.write_all(content.as_bytes())?;
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
