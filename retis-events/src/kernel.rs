use std::fmt;

use super::*;
use crate::{event_section, event_type, Formatter};

/// Kernel section.
#[event_section(SectionId::Kernel)]
#[derive(Default)]
pub struct KernelEvent {
    /// Symbol name. I.e: which probe generated the event.
    pub symbol: String,
    /// Probe type. One of "kprobe", "kretprobe" or "raw_tracepoint".
    pub probe_type: String,
    /// Stack trace.
    pub stack_trace: Option<StackTrace>,
}

impl EventFmt for KernelEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
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
pub struct StackTrace(pub Vec<String>);

impl StackTrace {
    pub fn raw(&self) -> &Vec<String> {
        &self.0
    }
}

impl EventFmt for StackTrace {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result {
        let last = self.0.len() - 1;
        if format.multiline {
            self.0.iter().enumerate().try_for_each(|(i, sym)| {
                write!(f, "{sym}")?;
                if i != last {
                    writeln!(f)?;
                }
                Ok(())
            })
        } else {
            write!(f, "[{}]", self.0.join(", "))
        }
    }
}
