use anyhow::Result;

use crate::core::events::Event;

/// Trait to process and output events.
pub(crate) trait Processor {
    /// Process and output events one by one.
    fn process_one(&mut self, e: &Event) -> Result<()>;
    /// Flush any pending output operations.
    fn flush(&mut self) -> Result<()>;
}
