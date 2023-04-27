//! Event formatting. Utilities to format Events strings in different formats
#![allow(dead_code)]
use anyhow::Result;

use super::Event;
use crate::output::Formatter;

#[derive(Default, Debug)]
pub(crate) struct FormatOpts {
    r#type: FormatType,
}

#[derive(Default, Debug)]
pub(crate) enum FormatType {
    #[default]
    Short,
}

// Trait that all EventSections (and global Event) must satisfy for them to be formatted
pub(crate) trait EventFormat {
    /// Format the event as a string according to the given format.
    fn format(&self, _format: &FormatOpts) -> String;
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
pub(crate) struct TextFormat {
    opts: FormatOpts,
}

impl Formatter for TextFormat {
    fn format_one(&mut self, e: &Event) -> Result<Vec<u8>> {
        Ok(e.format(&self.opts).into())
    }
}

impl TextFormat {
    #![allow(dead_code)]
    fn new(opts: FormatOpts) -> TextFormat {
        TextFormat { opts }
    }
}
