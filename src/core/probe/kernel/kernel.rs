#![allow(dead_code)] // FIXME

use std::fmt;

use anyhow::{bail, Result};

use super::{config::ProbeConfig, inspect::inspect_symbol};
use crate::core::{
    events::{
        bpf::{BpfEventOwner, BpfEvents},
        EventField,
    },
    kernel::Symbol,
};
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
}

impl fmt::Display for KernelProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.symbol)
    }
}

/// Registers the unmarshaler for the kernel section of the event.
pub(crate) fn register_unmarshaler(events: &mut BpfEvents) -> Result<()> {
    events.register_unmarshaler(
        BpfEventOwner::Kernel,
        Box::new(|raw_section, fields| {
            if raw_section.data.len() != 8 {
                bail!(
                    "Section data is not the expected size {} != 8",
                    raw_section.data.len()
                );
            }

            let symbol = u64::from_ne_bytes(raw_section.data[0..8].try_into()?);

            fields.push(event_field!("symbol", Symbol::from_addr(symbol)?.name()));
            Ok(())
        }),
    )?;
    Ok(())
}
