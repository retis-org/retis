use std::fmt;

use super::*;
use crate::{event_section, event_type};

#[event_section]
pub(crate) struct KernelEvent {
    /// Kernel symbol name associated with the event (i.e. which probe generated
    /// the event).
    pub(crate) symbol: String,
    /// Probe type: one of "kprobe", "kretprobe" or "raw_tracepoint".
    pub(crate) probe_type: String,
    pub(crate) stack_trace: Option<StackTrace>,
}

impl EventFmt for KernelEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        write!(
            f,
            "[{}] {}",
            match self.probe_type.as_str() {
                "raw_tracepoint" => "tp",
                "kprobe" => "k",
                "kretprobe" => "kr",
                _ => "invalid",
            },
            self.symbol,
        )?;

        Ok(())
    }
}

#[event_type]
#[derive(Default)]
pub(crate) struct StackTrace(pub(crate) Vec<String>);

impl StackTrace {
    pub(crate) fn raw(&self) -> &Vec<String> {
        &self.0
    }
}

impl EventFmt for StackTrace {
    fn event_fmt(&self, f: &mut fmt::Formatter, format: DisplayFormat) -> fmt::Result {
        let last = self.0.len() - 1;
        match format {
            DisplayFormat::SingleLine => {
                write!(f, "[{}]", self.0.join(", "))
            }
            DisplayFormat::MultiLine => self.0.iter().enumerate().try_for_each(|(i, sym)| {
                write!(f, "    {sym}")?;
                if i != last {
                    writeln!(f)?;
                }
                Ok(())
            }),
        }
    }
}
