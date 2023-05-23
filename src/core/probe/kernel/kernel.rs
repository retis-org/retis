#![allow(dead_code)] // FIXME

use std::fmt;

use anyhow::{bail, Result};

use super::{config::ProbeConfig, inspect::inspect_symbol};
use crate::core::{
    events::{bpf::BpfRawSection, *},
    kernel::Symbol,
    probe::ProbeOption,
};
use crate::{event_section, event_section_factory, EventSectionDisplay};

// Split to exclude from tests.
#[cfg(not(test))]
use crate::core::kernel::inspect;

/// Kernel encapsulates all the information about a kernel probe (kprobe or tracepoint) needed to attach to it.
#[derive(Clone)]
pub(crate) struct KernelProbe {
    pub(crate) symbol: Symbol,
}

impl KernelProbe {
    pub(crate) fn new(symbol: Symbol) -> Result<Self> {
        Ok(KernelProbe { symbol })
    }

    /// Generate the probe BPF configuration from a list of options.
    pub(crate) fn gen_config(&self, options: &[ProbeOption]) -> Result<ProbeConfig> {
        let mut config = inspect_symbol(&self.symbol)?;

        #[allow(clippy::single_match)]
        options.iter().for_each(|o| match o {
            ProbeOption::StackTrace => {
                config.stack_trace = 1;
            }
            _ => (),
        });

        Ok(config)
    }
}

impl fmt::Display for KernelProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.symbol)
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub(crate) struct StackTrace(Vec<String>);

impl fmt::Display for StackTrace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.iter().try_for_each(|x| write!(f, "{}", x))
    }
}

#[event_section]
#[derive(EventSectionDisplay)]
pub(crate) struct KernelEvent {
    /// Kernel symbol name associated with the event (i.e. which probe generated
    /// the event).
    pub(crate) symbol: String,
    /// Probe type: one of "kprobe", "kretprobe" or "raw_tracepoint".
    pub(crate) probe_type: String,
    pub(crate) stack_trace: Option<StackTrace>,
}

#[derive(Default)]
#[event_section_factory(KernelEvent)]
pub(crate) struct KernelEventFactory {
    #[cfg(not(test))]
    pub(crate) stack_map: Option<libbpf_rs::Map>,
}

impl KernelEventFactory {
    #[cfg(not(test))]
    fn unmarshal_stackid(&self, event: &mut KernelEvent, stackid: i32) -> Result<()> {
        if stackid >= 0 {
            let mut stack_trace: Vec<String> = Vec::new();
            // Only stack_map.lookup() gets intentionally performed. This means that at some point
            // it's possible that stack_map's entries could be exhausted.
            if let Some(stack_bytes) = self
                .stack_map
                .as_ref()
                .expect("Stack map is None")
                .lookup(&stackid.to_ne_bytes(), libbpf_rs::MapFlags::ANY)?
            {
                let sstack: &[u64] = unsafe {
                    std::slice::from_raw_parts(
                        stack_bytes.as_ptr() as *const u64,
                        stack_bytes.len() / std::mem::size_of::<u64>(),
                    )
                };

                for sym in sstack {
                    if *sym == 0x00_u64 {
                        break;
                    }

                    match inspect::get_name_offt_from_addr_near(*sym) {
                        Ok((symbol, offset)) => stack_trace.push(format!("{symbol}+{offset:#x}")),
                        Err(_) => stack_trace.push(format!("{sym:#x}")),
                    }
                }
            }

            event.stack_trace = Some(StackTrace(stack_trace));
        }
        Ok(())
    }
}

impl RawEventSectionFactory for KernelEventFactory {
    fn from_raw(&mut self, mut raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        if raw_sections.len() != 1 {
            bail!("Kernel event from BPF must be a single section");
        }

        // Unwrap as we just checked the vector contains 1 element.
        let raw = raw_sections.pop().unwrap();

        if raw.header.data_type != 1 {
            bail!("Unknown data type");
        }

        if raw.data.len() != 17 {
            bail!(
                "Section data is not the expected size {} != 17",
                raw.data.len()
            );
        }

        let mut event = KernelEvent::default();

        let symbol = u64::from_ne_bytes(raw.data[0..8].try_into()?);
        event.symbol = Symbol::from_addr(symbol)?.name();

        event.probe_type = match raw.data[8] {
            0 => "kprobe",
            1 => "kretprobe",
            2 => "raw_tracepoint",
            x => bail!("Unknown probe type {x}"),
        }
        .to_string();

        #[cfg(not(test))]
        self.unmarshal_stackid(
            &mut event,
            i64::from_ne_bytes(raw.data[9..17].try_into()?) as i32,
        )?;

        Ok(Box::new(event))
    }
}
