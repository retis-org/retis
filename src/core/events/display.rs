use std::fmt;

#[derive(Debug, Default, Clone, Copy, clap::ValueEnum)]
pub(crate) enum DisplayFormat {
    SingleLine,
    #[default]
    MultiLine,
}

/// Trait controlling how an event or an event section (or any custom type
/// inside it) is displayed. It works by providing an helper returning an
/// implementation of the std::fmt::Display trait, which can be used later to
/// provide different formats. It is also interesting as those helpers can take
/// arguments, unlike a plain std::fmt::Display implementation.
pub(crate) trait EventDisplay<'a>: EventFmt {
    /// Display the event using the default event format.
    fn display(&'a self, format: DisplayFormat) -> Box<dyn fmt::Display + 'a>;
}

/// Trait controlling how an event or an event section (or any custom type
/// inside it) is formatted.
///
/// Splitting this from EventDisplay allows to 1) not implement boilerplate for
/// all event sections and custom types thanks to the following generic
/// implementation and 2) access `self` directly allowing to access its private
/// members if any.
pub(crate) trait EventFmt {
    /// Default formatting of an event.
    fn event_fmt(&self, f: &mut fmt::Formatter, format: DisplayFormat) -> fmt::Result;
}

impl<'a, T> EventDisplay<'a> for T
where
    T: EventFmt,
{
    fn display(&'a self, format: DisplayFormat) -> Box<dyn fmt::Display + 'a> {
        struct DefaultDisplay<'a, U> {
            myself: &'a U,
            format: DisplayFormat,
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
