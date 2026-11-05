#![cfg_attr(test, allow(unused_imports, unused_variables, unused_mut))]

use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

use anyhow::Result;

use crate::{
    core::kernel::Symbol,
    events::{Event, KernelEvent},
};

/// Consumes stack traces and filter potential probes to add.
#[derive(Clone)]
pub(crate) struct ProbeStackFilter {
    /// Symbols we already saw.
    symbols: Arc<RwLock<HashSet<String>>>,
    /// Should all stack be kept?
    stack_all: bool,
    /// Otherwise, a list of symbols were the stack trace should be kept.
    stack_symbols: Arc<HashSet<String>>,
    /// Set of kernel types known by collectors, so we only probe functions that
    /// can generate an event.
    known_kernel_types: Arc<HashSet<String>>,
    /// Channel to send symbol candidates.
    txc: crossbeam_channel::Sender<String>,
}

impl ProbeStackFilter {
    pub(crate) fn new(
        stack_all: bool,
        stack_symbols: Arc<HashSet<String>>,
        known_kernel_types: Arc<HashSet<String>>,
        txc: crossbeam_channel::Sender<String>,
    ) -> Self {
        Self {
            symbols: Arc::new(RwLock::new(HashSet::new())),
            stack_all,
            stack_symbols,
            known_kernel_types,
            txc,
        }
    }

    fn keep_stack(&self, evt: &KernelEvent) -> bool {
        let r#type = match evt.probe_type.as_str() {
            "raw_tracepoint" => "tp",
            s => s,
        };
        let sym = format!("{}:{}", r#type, evt.symbol);
        self.stack_symbols.contains(&sym)
    }

    /// Process a new event and detect additional functions to add a probe too.
    /// This is called in the event retrieval logic and should try not to
    /// propagate non-fatal errors.
    pub(crate) fn process_event(&self, event: &mut Event) -> Result<()> {
        let kernel = match &mut event.kernel {
            Some(kernel) => kernel,
            None => return Ok(()),
        };
        let stack = match &kernel.stack_trace {
            Some(stack) => stack,
            None => return Ok(()),
        };

        stack.raw().iter().try_for_each(|line| -> Result<()> {
            let func = match line.split_once('+') {
                Some((func, _)) => func,
                _ => return Ok(()),
            };

            // Check if we already saw the symbol.
            if self.symbols.read().unwrap().contains(func) {
                return Ok(());
            }
            self.symbols.write().unwrap().insert(func.to_string());

            let symbol = match Symbol::from_name(func) {
                Ok(symbol) => symbol,
                _ => return Ok(()),
            };

            // Filter out symbols not operating on a type we can retrieve
            // data from.
            let params = symbol.get_parameters()?;
            if !self
                .known_kernel_types
                .iter()
                .any(|t| params.iter().any(|(_, p)| p == t))
            {
                return Ok(());
            }

            let _ = self.txc.send(func.to_string());
            Ok(())
        })?;

        // Remove the stack trace from the event if not explicity wanted.
        if !self.stack_all && !self.keep_stack(kernel) {
            kernel.stack_trace = None;
        }

        Ok(())
    }
}
