use std::io::Write;

use crate::core::events::Event;
use anyhow::Result;

/// Trait to output events
pub(crate) trait Output {
    /// Output events one by one.
    fn output_one(&mut self, e: &Event) -> Result<()>;
    /// Flush any pending output operations.
    fn flush(&mut self) -> Result<()>;
}

/// Trait to format events before output processing.
pub(crate) trait Formatter {
    /// Format events one by one.
    fn format_one(&mut self, e: &Event) -> Result<Vec<u8>>;
}

/// Takes a Formatter and one-or-more Write and combines them for handling events.
pub(crate) struct FormatAndWrite {
    formatter: Box<dyn Formatter>,
    writers: Vec<Box<dyn Write>>,
}

impl FormatAndWrite {
    pub(crate) fn new(formatter: Box<dyn Formatter>, writers: Vec<Box<dyn Write>>) -> Self {
        FormatAndWrite { formatter, writers }
    }
}

impl Output for FormatAndWrite {
    fn output_one(&mut self, e: &Event) -> Result<()> {
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
