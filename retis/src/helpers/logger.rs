use std::{
    env,
    io::{stderr, IsTerminal, Stdout, Write},
    sync::{Arc, Mutex},
};

use anyhow::Result;
use log::{info, trace, warn, LevelFilter, Metadata, Record};
use termcolor::{BufferedStandardStream, Color, ColorChoice, ColorSpec, WriteColor};
use time::{macros::format_description, OffsetDateTime};

#[derive(Debug)]
/// Our own logger implementation, to handle log:: messages.
pub(crate) struct Logger {
    /// Max level the logger will output.
    max_level: LevelFilter,
    /// Inner writer, alongside its configuration.
    inner: Mutex<LoggerWriter>,
}

#[derive(Debug)]
struct LoggerWriter {
    /// We're only outputting messages to stderr, as non-log output is printed
    /// on stdout. This allows to not mix the two and even pipe the non-log
    /// output to other tools. `switch_to_stdout()` can be used to disable this
    /// behavior for specific cases.
    stderr: BufferedStandardStream,
    /// Should colors be used in the output?
    use_colors: bool,
}

impl Logger {
    pub(crate) fn init(max_level: LevelFilter) -> Result<Arc<Self>> {
        let logger = Arc::new(Logger {
            max_level,
            inner: Mutex::new(LoggerWriter {
                stderr: BufferedStandardStream::stderr(ColorChoice::Auto),
                use_colors: Self::check_color_use(Some(stderr())),
            }),
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
        let inner: &mut LoggerWriter = &mut self.inner.lock().unwrap();

        // If the log level allows debug! and/or trace!, show the time.
        if self.max_level >= LevelFilter::Debug {
            OffsetDateTime::now_utc().format_into(
                &mut inner.stderr,
                format_description!("[hour]:[minute]:[second].[subsecond digits:6] "),
            )?;
        }

        // Show the level for error! and warn!, or if the max level includes
        // debug!.
        if record.level() <= LevelFilter::Warn || self.max_level >= LevelFilter::Debug {
            if inner.use_colors {
                inner
                    .stderr
                    .set_color(ColorSpec::new().set_fg(LEVEL_COLORS[record.level() as usize]))?;
            }
            write!(inner.stderr, "{:5} ", record.level(),)?;
            if inner.use_colors {
                inner.stderr.reset()?;
            }
        }

        writeln!(inner.stderr, "{}", record.args())?;

        inner.stderr.flush()?;
        Ok(())
    }

    /// Switch the output from stderr to stdout. Used in some specific cases,
    /// like when a pager is used.
    pub(crate) fn switch_to_stdout(&self) {
        let mut inner = self.inner.lock().unwrap();

        // We know a pager is used, do not check the descriptor. This ensure
        // we'll force color output in the pager (if the underlying terminal
        // supports it).
        inner.use_colors = Self::check_color_use::<Stdout>(None);
        inner.stderr = BufferedStandardStream::stdout(if inner.use_colors {
            ColorChoice::Always
        } else {
            ColorChoice::Never
        });
    }

    /// Check if colors can be used in the output.
    fn check_color_use<T: IsTerminal>(t: Option<T>) -> bool {
        if let Some(t) = t {
            if !t.is_terminal() {
                return false;
            }
        }
        if !matches!(env::var("TERM"), Ok(x) if x != "dumb") {
            return false;
        }
        true
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
        let _ = self.inner.lock().unwrap().stderr.flush();
    }
}

pub(crate) fn set_libbpf_rs_print_callback(level: LevelFilter) {
    let libbpf_rs_print = |level, msg: String| {
        let msg = msg.trim_end_matches('\n');
        match level {
            libbpf_rs::PrintLevel::Debug => trace!("{msg}"),
            libbpf_rs::PrintLevel::Info => info!("{msg}"),
            libbpf_rs::PrintLevel::Warn => warn!("{msg}"),
        }
    };

    libbpf_rs::set_print(match level {
        LevelFilter::Error | LevelFilter::Off => None,
        LevelFilter::Warn => Some((libbpf_rs::PrintLevel::Warn, libbpf_rs_print)),
        LevelFilter::Info | LevelFilter::Debug => {
            Some((libbpf_rs::PrintLevel::Info, libbpf_rs_print))
        }
        LevelFilter::Trace => Some((libbpf_rs::PrintLevel::Debug, libbpf_rs_print)),
    });
}
