#![cfg_attr(test, allow(unused_imports, unused_variables, unused_mut))]

use std::collections::HashSet;

use anyhow::Result;
use btf_rs::Type;
use log::{debug, warn};

use crate::{
    core::{
        inspect::inspector,
        kernel::Symbol,
        probe::{kernel::KernelEvent, Probe, ProbeRuntimeManager},
    },
    events::Event,
    module::ModuleId,
};

/// Probe-stack consume stack traces and add additional probes for compatible
/// functions found there.
pub(crate) struct ProbeStack {
    /// Local cache of functions that were already considered, probed or not.
    /// Used to optimize the event processing.
    probes: HashSet<String>,
    /// Should the stack stay in the event?
    keep_stack: bool,
    /// Set of kernel types known by collectors, so we only probe functions that
    /// can generate an event.
    known_kernel_types: HashSet<String>,
}

impl ProbeStack {
    pub(crate) fn new(
        keep_stack: bool,
        attached_probes: Vec<String>,
        known_kernel_types: HashSet<String>,
    ) -> Self {
        // Stack probe mode works with kprobes only and keeps track of the
        // function name.
        let attached_probes = attached_probes
            .iter()
            .filter_map(|p| p.strip_prefix("kprobe:"))
            .map(|p| p.to_string())
            .collect::<Vec<String>>();

        Self {
            probes: HashSet::from_iter(attached_probes),
            keep_stack,
            known_kernel_types,
        }
    }

    /// Process a new event and detect additional functions to add a probe too.
    /// This is called in the event retrieval logic and should try not to
    /// propagate non-fatal errors.
    pub(crate) fn process_event(
        &mut self,
        mgr: &mut ProbeRuntimeManager,
        event: &mut Event,
    ) -> Result<()> {
        let kernel = match event.get_section_mut::<KernelEvent>(ModuleId::Kernel) {
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

            if self.probes.insert(func.to_string()) {
                // Filter out functions not having a BTF representation.
                let types = inspector()?.kernel.btf.resolve_types_by_name(func);
                if types.is_err()
                    || !types
                        .unwrap()
                        .iter()
                        .any(|(_, t)| matches!(t, Type::Func(_)))
                {
                    return Ok(());
                }

                let symbol = match Symbol::from_name(func) {
                    Ok(symbol) => symbol,
                    _ => return Ok(()),
                };

                // Filter out symbols not operating on a type we can retrieve
                // data from.
                if !self
                    .known_kernel_types
                    .iter()
                    .any(|t| match symbol.parameter_offset(t) {
                        Ok(ret) => ret.is_some(),
                        _ => false,
                    })
                {
                    return Ok(());
                }

                let mut probe = match Probe::kprobe(symbol) {
                    Ok(probe) => probe,
                    _ => return Ok(()),
                };

                #[cfg(not(test))]
                if let Err(e) = mgr.attach_generic_probe(&mut probe) {
                    warn!("Could not attach additional probe {probe}: {e}");
                    return Ok(());
                }

                debug!("Added probe to {}", func);
            }

            Ok(())
        })?;

        if !self.keep_stack {
            kernel.stack_trace = None;
        }

        Ok(())
    }
}
