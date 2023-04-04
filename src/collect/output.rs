use std::{
    fs::OpenOptions,
    io::{self, BufWriter, Write},
};

use anyhow::{bail, Result};

use super::cli::CollectArgs;
use crate::core::events::Event;

/// Given a Formatter and cli arguments, get a list of output processors, for
/// later event output processing.
pub(super) fn get_processors<'a, F: Formatter>(
    formatter: &'a mut F,
    args: &CollectArgs,
) -> Result<Vec<Box<dyn Processor + 'a>>> {
    // The actual output selection will be decided by the user (--out and/or
    // --print) below.
    let mut writers: Vec<Box<dyn Write>> = Vec::new();

    // Write the events to a file if asked to.
    if let Some(out) = args.out.as_ref() {
        writers.push(Box::new(BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(out)
                .or_else(|_| bail!("Could not create or open '{}'", out.display()))?,
        )));
    }

    // Write events to stdout if we don't write to a file (--out) or if
    // explicitly asked to (--print).
    if args.out.is_none() || args.print {
        writers.push(Box::new(io::stdout()));
    }

    Ok(vec![Box::new(FormatAndWrite::new(formatter, writers))])
}

/// Trait to process and output events.
pub(super) trait Processor {
    /// Process and output events one by one.
    fn process_one(&mut self, e: &Event) -> Result<()>;
    /// Flush any pending output operations.
    fn flush(&mut self) -> Result<()>;
}

/// Trait to format events before output processing.
pub(super) trait Formatter {
    /// Format events one by one.
    fn format_one(&mut self, e: &Event) -> Result<Vec<u8>>;
}

/// Takes a Formatter and one-or-more Write and combines them for handling
/// events.
pub(super) struct FormatAndWrite<'a, F>
where
    F: Formatter,
{
    formatter: &'a mut F,
    writers: Vec<Box<dyn Write>>,
}

impl<'a, F> FormatAndWrite<'a, F>
where
    F: Formatter,
{
    pub(super) fn new(formatter: &'a mut F, writers: Vec<Box<dyn Write>>) -> Self {
        FormatAndWrite { formatter, writers }
    }
}

impl<'a, F> Processor for FormatAndWrite<'a, F>
where
    F: Formatter,
{
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
pub(super) struct JsonFormat {}

impl Formatter for JsonFormat {
    fn format_one(&mut self, e: &Event) -> Result<Vec<u8>> {
        Ok(e.to_json().to_string().as_bytes().to_vec())
    }
}
