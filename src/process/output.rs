use std::io::Write;

use crate::core::events::Event;
use anyhow::Result;

use super::Processor;

/// Trait to format events before output processing.
pub(crate) trait Formatter {
    /// Format events one by one.
    fn format_one(&mut self, e: &Event) -> Result<Vec<u8>>;
}

/// Takes a Formatter and one-or-more Write and combines them for handling
/// events.
pub(crate) struct FormatAndWrite {
    formatter: Box<dyn Formatter>,
    writers: Vec<Box<dyn Write>>,
}

impl FormatAndWrite {
    pub(crate) fn new(formatter: Box<dyn Formatter>, writers: Vec<Box<dyn Write>>) -> Self {
        FormatAndWrite { formatter, writers }
    }
}

impl Processor for FormatAndWrite {
    fn process_one(&mut self, e: &Event) -> Result<()> {
        let bytes = self.formatter.format_one(e)?;
        for w in &mut self.writers {
            w.write_all(&bytes)?;
            w.write_all(b"\n")?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        for w in &mut self.writers {
            w.flush()?;
        }
        Ok(())
    }
}

/// Formatter to get events in JSON.
#[derive(Default)]
pub(crate) struct JsonFormat {}

impl Formatter for JsonFormat {
    fn format_one(&mut self, e: &Event) -> Result<Vec<u8>> {
        Ok(e.to_json().to_string().as_bytes().to_vec())
    }
}

/// Formatter to get events in Text.
#[derive(Default)]
pub(crate) struct TextFormat {}

impl Formatter for TextFormat {
    fn format_one(&mut self, e: &Event) -> Result<Vec<u8>> {
        Ok(e.to_string().into())
    }
}
