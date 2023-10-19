use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use log::{LevelFilter, Metadata, Record};
use termcolor::{BufferedStandardStream, Color, ColorChoice, ColorSpec, WriteColor};
use time::{macros::format_description, OffsetDateTime};

/// Our own logger implementation, to handle log:: messages.
pub(crate) struct Logger {
    /// Max level the logger will output.
    max_level: LevelFilter,
    /// We're only outputting messages to stderr, as non-log output is printed
    /// on stdout. This allows to not mix the two and even pipe the non-log
    /// output to other tools. `switch_to_stdout()` can be used to disable this
    /// behavior for specific cases.
    stderr: Mutex<BufferedStandardStream>,
}

impl Logger {
    pub(crate) fn init(max_level: LevelFilter) -> Result<Arc<Self>> {
        let logger = Arc::new(Logger {
            max_level,
            stderr: Mutex::new(BufferedStandardStream::stderr(ColorChoice::Auto)),
        });

        log::set_max_level(max_level);
        log::set_boxed_logger(Box::new(Arc::clone(&logger)))?;

        Ok(logger)
    }

    pub(crate) fn try_log(&self, record: &Record) -> Result<()> {
        static LEVEL_COLORS: &[Option<Color>] = &[
            None,                // Default.
            Some(Color::Red),    // Error.
            Some(Color::Yellow), // Warn.
            Some(Color::Blue),   // Info.
            Some(Color::Cyan),   // Debug.
            Some(Color::White),  // Trace.
        ];
        let mut stderr: &mut BufferedStandardStream = &mut self.stderr.lock().unwrap();

        // If the log level allows debug! and/or trace!, show the time.
        if self.max_level >= LevelFilter::Debug {
            OffsetDateTime::now_utc().format_into(
                &mut stderr,
                format_description!("[hour]:[minute]:[second].[subsecond digits:6] "),
            )?;
        }

        // Show the level for error! and warn!, or if the max level includes
        // debug!.
        if record.level() <= LevelFilter::Warn || self.max_level >= LevelFilter::Debug {
            stderr.set_color(ColorSpec::new().set_fg(LEVEL_COLORS[record.level() as usize]))?;
            write!(stderr, "{:5} ", record.level(),)?;
            stderr.reset()?;
        }

        writeln!(stderr, "{}", record.args())?;

        stderr.flush()?;
        Ok(())
    }

    /// Switch the output from stderr to stdout. Used in some specific cases,
    /// like when a pager is used.
    pub(crate) fn switch_to_stdout(&self) {
        let mut stderr = self.stderr.lock().unwrap();
        *stderr = BufferedStandardStream::stdout(ColorChoice::Auto);
    }
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // Not much we can do to report the error...
        let _ = self.try_log(record);
    }

    fn flush(&self) {
        // Not much we can do to report the error...
        let _ = self.stderr.lock().unwrap().flush();
    }
}
