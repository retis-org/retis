use std::fmt;

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
}

/// Trait controlling how an event or an event section (or any custom type
/// inside it) is displayed. It works by providing an helper returning an
/// implementation of the std::fmt::Display trait, which can be used later to
/// provide different formats. It is also interesting as those helpers can take
/// arguments, unlike a plain std::fmt::Display implementation.
pub trait EventDisplay<'a>: EventFmt {
    /// Display the event using the default event format.
    fn display(&'a self, format: &'a DisplayFormat) -> Box<dyn fmt::Display + 'a>;
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
    fn event_fmt(&self, f: &mut fmt::Formatter, format: &DisplayFormat) -> fmt::Result;
}

impl<'a, T> EventDisplay<'a> for T
where
    T: EventFmt,
{
    fn display(&'a self, format: &'a DisplayFormat) -> Box<dyn fmt::Display + 'a> {
        struct DefaultDisplay<'a, U> {
            myself: &'a U,
            format: &'a DisplayFormat,
        }
        impl<U: EventFmt> fmt::Display for DefaultDisplay<'_, U> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.myself.event_fmt(f, self.format)
            }
        }
        Box::new(DefaultDisplay {
            myself: self,
            format,
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
/// use retis_events::DelimWriter;
///
/// struct Flags {
///     opt1: bool,
///     opt2: bool,
/// }
/// impl fmt::Display for Flags {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         write!(f, "flags")?;
///         let mut space = DelimWriter::new(' ');
///         if self.opt1 {
///             space.write(f)?;
///             write!(f, "opt1");
///          }
///         if self.opt2 {
///             space.write(f)?;
///             write!(f, "opt2")?;
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
    pub fn write(&mut self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.first {
            true => self.first = false,
            false => write!(f, "{}", self.delim)?,
        }
        Ok(())
    }
}
