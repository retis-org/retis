#![allow(dead_code)] // FIXME

use std::{collections::HashMap, fmt};

use anyhow::{bail, Result};

use super::{config::ProbeConfig, inspect::inspect_symbol};
use crate::{
    core::{
        events::{
            parse_single_raw_section, BpfRawSection, EventSectionFactory, FactoryId,
            RawEventSectionFactory,
        },
        kernel::Symbol,
        probe::{
            common::{Counters, CountersKey},
            ProbeOption,
        },
    },
    event_section_factory,
    events::*,
    raw_event_section,
};

// Split to exclude from tests.
#[cfg(not(test))]
use crate::{core::inspect::inspector, events::kernel::StackTrace};

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

    /// Generate the probe BPF configuration from a list of options.
    pub(crate) fn gen_counters(&self) -> Result<(CountersKey, Counters)> {
        Ok((
            CountersKey {
                sym_addr: self.symbol.addr()?,
                ..Default::default()
            },
            Counters::default(),
        ))
    }
}

impl fmt::Display for KernelProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.symbol)
    }
}

#[event_section_factory(FactoryId::Kernel)]
#[derive(Default)]
pub(crate) struct KernelEventFactory {
    #[cfg(not(test))]
    pub(crate) stack_map: Option<libbpf_rs::MapHandle>,
    // Cache of symbol addr -> name
    symbols_cache: HashMap<u64, String>,
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

                    match inspector()?.kernel.get_name_offt_from_addr_near(*sym) {
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

#[raw_event_section]
pub(crate) struct RawKernelEvent {
    symbol: u64,
    r#type: u8,
    stack_id: u64,
}

impl RawEventSectionFactory for KernelEventFactory {
    fn create(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let raw = parse_single_raw_section::<RawKernelEvent>(&raw_sections)?;
        let mut event = KernelEvent::default();

        let symbol_addr = raw.symbol;
        event.symbol = match self.symbols_cache.get(&symbol_addr) {
            Some(name) => name.clone(),
            None => {
                let name = Symbol::from_addr(symbol_addr)?.name();
                self.symbols_cache.insert(symbol_addr, name.clone());
                name
            }
        };

        event.probe_type = match raw.r#type {
            0 => "kprobe",
            1 => "kretprobe",
            2 => "raw_tracepoint",
            x => bail!("Unknown probe type {x}"),
        }
        .to_string();

        #[cfg(not(test))]
        self.unmarshal_stackid(&mut event, raw.stack_id as i32)?;

        Ok(Box::new(event))
    }
}

#[cfg(feature = "benchmark")]
pub(crate) mod benchmark {
    use anyhow::Result;

    use super::RawKernelEvent;
    use crate::{benchmark::helpers::*, core::kernel::Symbol, events::SectionId};

    impl RawSectionBuilder for RawKernelEvent {
        fn build_raw(out: &mut Vec<u8>) -> Result<()> {
            let data = RawKernelEvent {
                symbol: Symbol::from_name("openvswitch:ovs_do_execute_action")?.addr()?,
                r#type: 2, // Raw tracepoint.
                stack_id: u64::MAX,
            };
            build_raw_section(out, SectionId::Kernel.to_u8(), 0, &mut as_u8_vec(&data));
            Ok(())
        }
    }
}
