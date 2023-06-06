use std::io::Write;

use anyhow::Result;

use crate::core::events::*;

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
        let event = match self.format {
            PrintSingleFormat::Text(format) => match format {
                DisplayFormat::SingleLine => format!("{}\n", e.display(format)),
                DisplayFormat::MultiLine => format!("\n{}\n", e.display(format)),
            },
            PrintSingleFormat::Json => format!("{}\n", e.to_json()),
        };

        Ok(self.writer.write_all(event.as_bytes())?)
    }

    /// Flush underlying writers.
    pub(crate) fn flush(&mut self) -> Result<()> {
        Ok(self.writer.flush()?)
    }
}
