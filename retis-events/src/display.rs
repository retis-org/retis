use std::{
    fmt::{self, Write},
    result, str,
};

use log::warn;

use super::TimeSpec;

/// Controls how the time should be displayed in the events.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub enum TimeFormat {
    #[default]
    MonotonicTimestamp,
    UtcDate,
}

/// Controls how an event is formatted.
#[derive(Debug, Default, Clone, Copy)]
pub struct DisplayFormat {
    /// Can the formatting logic use more than a single line?
    pub multiline: bool,
    /// How the time is formatted.
    pub time_format: TimeFormat,
    /// Offset of the monotonic clock to the wall-clock time.
    pub monotonic_offset: Option<TimeSpec>,
    /// Should the link level part be displayed?
    pub print_ll: bool,
}

impl DisplayFormat {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure multi-line output.
    pub fn multiline(mut self, enabled: bool) -> Self {
        self.multiline = enabled;
        self
    }

    /// Configure how the time will be formatted.
    pub fn time_format(mut self, format: TimeFormat) -> Self {
        self.time_format = format;
        self
    }

    /// Sets the monotonic clock to the wall-clock time.
    pub fn monotonic_offset(mut self, offset: TimeSpec) -> Self {
        self.monotonic_offset = Some(offset);
        self
    }

    /// Configure if LL information is printed.
    pub fn print_ll(mut self, enabled: bool) -> Self {
        self.print_ll = enabled;
        self
    }
}

/// `Formatter` implements `std::fmt::Write` and controls how events are being
/// displayed.  This is similar to `std::fmt::Formatter` but with our own
/// constraints.
///
/// It supports the following capabilities: indentation and itemization. Each of
/// those are always context-based: the capabilities and their configuration can
/// change over time and might end based on input (eg. itemization).
pub struct Formatter<'a, 'inner> {
    inner: &'a mut fmt::Formatter<'inner>,
    pub conf: FormatterConf,
    /// Indentation level (in spaces).
    level: usize,
    /// True if the next input is the start of a block (aka. first call to
    /// `flush_buf`).
    first: bool,
    /// True if the next input is the start of a line.
    start: bool,
    /// Buffer holding the output before being flushed.
    buf: String,
}

impl<'a, 'inner> Formatter<'a, 'inner> {
    pub fn new(
        inner: &'a mut fmt::Formatter<'inner>,
        conf: FormatterConf,
    ) -> Formatter<'a, 'inner> {
        let level = conf.level;

        Self {
            inner,
            conf,
            level,
            first: true,
            start: true,
            buf: String::with_capacity(4096usize),
        }
    }

    /// Directly implement write_fmt to avoid the need of an explicit
    /// `use fmt::Write` by every user. See the `std::write` documentation.
    #[inline]
    pub fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> result::Result<(), fmt::Error> {
        <Self as fmt::Write>::write_fmt(self, args)
    }

    pub fn flush_buf(&mut self) -> result::Result<(), fmt::Error> {
        let first = self.first;
        match self.buf.is_empty() {
            true => return Ok(()),
            false => self.first = false,
        }

        let mut lines = self.buf.split('\n');

        // Compute the prefix including the itemization char, if any.
        let mut prefix = " ".repeat(self.level);
        if first && self.level >= 2 {
            if let Some(item) = self.conf.item {
                prefix.replace_range(self.level - 2..self.level - 1, &item.to_string());
            }
        }

        if let Some(line) = lines.next() {
            if self.start {
                self.start = false;
                self.inner.write_str(&prefix)?;
            }
            self.inner.write_str(line)?;
        }

        // Reset the itemization char, if any.
        if first && self.level >= 2 && self.conf.item.is_some() {
            prefix = " ".repeat(self.level);
        }

        // If the buffer ends with a newline, the last split will be empty. In
        // such case only print the newline.
        lines.try_for_each(|line| {
            self.inner.write_char('\n')?;
            if !line.is_empty() {
                self.inner.write_str(&prefix)?;
                self.inner.write_str(line)?;
            }
            Ok(())
        })?;

        if self.buf.ends_with('\n') {
            self.start = true;
        }

        self.buf.clear();
        Ok(())
    }
}

impl fmt::Write for Formatter<'_, '_> {
    fn write_str(&mut self, s: &str) -> result::Result<(), fmt::Error> {
        if self.conf.level != self.level {
            if !self.buf.is_empty() {
                self.flush_buf()?;
            }
            self.level = self.conf.level;
        }

        self.buf.push_str(s);
        Ok(())
    }
}

impl Drop for Formatter<'_, '_> {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            self.flush_buf().expect("Could not flush Formatter buffer");
        }
    }
}

/// Configuration for the `Formatter`. It can be shared between multiple
/// `EventDisplay::display` calls but its scope is restricted to a single call.
/// This means a base configuration can be shared for multiple
/// `EventDisplay::display` call but any modification made within an
/// `EventDisplay::display` call won't be visibile outside.
#[derive(Clone, Default)]
pub struct FormatterConf {
    level: usize,
    saved_levels: Vec<usize>,
    item: Option<char>,
}

impl FormatterConf {
    pub fn new() -> Self {
        Self::with_level(0)
    }

    pub fn with_level(level: usize) -> Self {
        Self {
            level,
            ..Default::default()
        }
    }

    /// Increase the indentation level by `diff`.
    pub fn inc_level(&mut self, diff: usize) {
        self.saved_levels.push(self.level);
        self.level += diff;
    }

    /// Reset the indentation level to its previous value.
    pub fn reset_level(&mut self) {
        match self.saved_levels.pop() {
            Some(level) => {
                self.level = level;
            }
            None => warn!("Cannot reset the indentation level"),
        }
    }

    /// Set an itemization char to be printed at the start of output, or None.
    pub fn set_item(&mut self, item: Option<char>) {
        self.item = item;
    }
}

/// Trait controlling how an event or an event section (or any custom type
/// inside it) is displayed. It works by providing a helper returning an
/// implementation of the std::fmt::Display trait, which can be used later to
/// provide different formats. It is also interesting as those helpers can take
/// arguments, unlike a plain std::fmt::Display implementation.
pub trait EventDisplay<'a>: EventFmt {
    /// Display the event using the default event format.
    fn display(
        &'a self,
        format: &'a DisplayFormat,
        conf: &'a FormatterConf,
    ) -> Box<dyn fmt::Display + 'a>;
}

/// Trait controlling how an event or an event section (or any custom type
/// inside it) is formatted.
///
/// Splitting this from EventDisplay allows to 1) not implement boilerplate for
/// all event sections and custom types thanks to the following generic
/// implementation and 2) access `self` directly allowing to access its private
/// members if any.
pub trait EventFmt {
    /// Default formatting of an event.
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result;
    /// Reports if the event section contains any formatable data when using the
    /// provided `DisplayFormat`.
    fn can_format(&self, _: &DisplayFormat) -> bool {
        true
    }
}

impl<'a, T> EventDisplay<'a> for T
where
    T: EventFmt,
{
    fn display(
        &'a self,
        format: &'a DisplayFormat,
        conf: &'a FormatterConf,
    ) -> Box<dyn fmt::Display + 'a> {
        struct DefaultDisplay<'a, U> {
            myself: &'a U,
            format: &'a DisplayFormat,
            conf: &'a FormatterConf,
        }
        impl<U: EventFmt> fmt::Display for DefaultDisplay<'_, U> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.myself
                    .event_fmt(&mut Formatter::new(f, self.conf.clone()), self.format)
            }
        }
        Box::new(DefaultDisplay {
            myself: self,
            format,
            conf,
        })
    }
}

/// DelimWriter is a simple helper that prints a character delimiter (e.g: ',' or ' ') only if it's
/// not the first time write() is called. This helps print lists of optional fields.
///
/// # Example:
///
/// ```
/// use std::fmt;
/// use retis_events::{Formatter, FormatterConf, DelimWriter};
///
/// struct Flags {
///     opt1: bool,
///     opt2: bool,
/// }
/// impl fmt::Display for Flags {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         let mut f = Formatter::new(f, FormatterConf::new());
///
///         write!(&mut f, "flags")?;
///         let mut space = DelimWriter::new(' ');
///         if self.opt1 {
///             space.write(&mut f)?;
///             write!(&mut f, "opt1");
///          }
///         if self.opt2 {
///             space.write(&mut f)?;
///             write!(&mut f, "opt2")?;
///          }
///          Ok(())
///     }
/// }
/// ```
pub struct DelimWriter {
    delim: char,
    first: bool,
}

impl DelimWriter {
    /// Create a new DelimWriter
    pub fn new(delim: char) -> Self {
        DelimWriter { delim, first: true }
    }

    /// If it's not the first time it's called, write the delimiter.
    pub fn write(&mut self, f: &mut Formatter) -> fmt::Result {
        match self.first {
            true => self.first = false,
            false => write!(f, "{}", self.delim)?,
        }
        Ok(())
    }

    /// Reset the DelimWriter to behave as if it was new.
    pub fn reset(&mut self) {
        self.first = true;
    }

    /// Was the DelimWriter used?
    pub fn used(&self) -> bool {
        !self.first
    }
}
