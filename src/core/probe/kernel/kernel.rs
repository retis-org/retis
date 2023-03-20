#![allow(dead_code)] // FIXME

use std::fmt;

use anyhow::{bail, Result};

use super::{config::ProbeConfig, inspect::inspect_symbol};
use crate::{
    core::{
        events::{
            bpf::{BpfEvents, BpfRawSection, EventUnmarshaler},
            EventField,
        },
        kernel::Symbol,
        probe::ProbeOption,
    },
    module::ModuleId,
};

// Split to exclude from tests.
#[cfg(not(test))]
use crate::core::kernel::inspect;

use crate::event_field;

/// Kernel encapsulates all the information about a kernel probe (kprobe or tracepoint) needed to attach to it.
pub(crate) struct KernelProbe {
    /// Symbol name
    pub(crate) symbol: Symbol,
    /// Symbol address
    pub(crate) ksym: u64,
    /// Number of arguments
    pub(crate) nargs: u32,
    /// Holds the different offsets to known parameters.
    pub(crate) config: ProbeConfig,
}

impl KernelProbe {
    pub(crate) fn new(symbol: Symbol) -> Result<Self> {
        let desc = inspect_symbol(&symbol)?;
        Ok(KernelProbe {
            symbol,
            ksym: desc.ksym,
            nargs: desc.nargs,
            config: desc.probe_cfg,
        })
    }

    /// Set, for probes only, a single config option used to change the default probe behavior.
    pub(crate) fn set_option(&mut self, opt: &ProbeOption) {
        match opt {
            ProbeOption::StackTrace => {
                self.config.stack_trace = 1;
            }
        }
    }
}

impl fmt::Display for KernelProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.symbol)
    }
}

struct KernelUnmarshaler {
    #[cfg(not(test))]
    stack_map: libbpf_rs::Map,
}

impl KernelUnmarshaler {
    #[cfg(not(test))]
    fn unmarshal_stackid(&self, fields: &mut Vec<EventField>, stackid: i32) -> Result<()> {
        if stackid >= 0 {
            let mut stack_trace: Vec<String> = Vec::new();
            // Only stack_map.lookup() gets intentionally performed. This means that at some point
            // it's possible that stack_map's entries could be exhausted.
            if let Some(stack_bytes) = self
                .stack_map
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

            fields.push(event_field!("stack_trace", stack_trace));
        }
        Ok(())
    }
}

impl EventUnmarshaler for KernelUnmarshaler {
    fn unmarshal(
        &mut self,
        raw_section: &BpfRawSection,
        fields: &mut Vec<EventField>,
    ) -> Result<()> {
        if raw_section.data.len() != 17 {
            bail!(
                "Section data is not the expected size {} != 17",
                raw_section.data.len()
            );
        }

        let symbol = u64::from_ne_bytes(raw_section.data[0..8].try_into()?);
        fields.push(event_field!("symbol", Symbol::from_addr(symbol)?.name()));

        let probe_type = raw_section.data[8];
        let probe_type_str = match probe_type {
            0 => "kprobe",
            1 => "kretprobe",
            2 => "raw_tracepoint",
            _ => bail!("Unknown probe type {probe_type}"),
        };
        fields.push(event_field!("probe_type", probe_type_str.to_string()));
        #[cfg(not(test))]
        self.unmarshal_stackid(
            fields,
            i64::from_ne_bytes(raw_section.data[9..17].try_into()?) as i32,
        )?;
        Ok(())
    }
}

/// Registers the unmarshaler for the kernel section of the event.
pub(crate) fn register_unmarshaler(
    events: &mut BpfEvents,
    #[cfg(not(test))] stackmap: libbpf_rs::Map,
) -> Result<()> {
    let unmarshaler = KernelUnmarshaler {
        #[cfg(not(test))]
        stack_map: stackmap,
    };

    events.register_unmarshaler(ModuleId::Kernel, Box::new(unmarshaler))?;
    Ok(())
}
