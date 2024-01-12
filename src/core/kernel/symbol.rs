use std::fmt;

use anyhow::{bail, Result};

use crate::core::inspect::inspector;

/// Kernel symbol representation. Only supports traceable symbols: events and
/// functions.
#[derive(Clone)]
pub(crate) enum Symbol {
    Event(String),
    Func(String),
}

impl Symbol {
    /// Check a Symbol is valid before returning it.
    fn check(self) -> Result<Symbol> {
        if self.addr().is_err() {
            bail!(
                "Symbol {} is not supported (no corresponding symbol address)",
                self
            );
        }

        if inspector()?.kernel.btf.find_prototype_btf(&self).is_err() {
            bail!(
                "Symbol {} is not supported (no corresponding BTF definition)",
                self
            );
        }

        Ok(self)
    }

    /// Create a new symbol given its name. We'll try hard to induce its type,
    /// using different techniques depending on what is available.
    pub(crate) fn from_name(name: &str) -> Result<Symbol> {
        let mut debugfs = false;

        // First try to see if the symbol is a traceable event.
        if let Some(traceable) = inspector()?.kernel.is_event_traceable(name) {
            debugfs = true;
            if traceable {
                return Symbol::Event(name.to_string()).check();
            }
        }

        // Then try to see if it's a traceable function.
        if let Some(traceable) = inspector()?.kernel.is_function_traceable(name) {
            if traceable {
                return Symbol::Func(name.to_string()).check();
            }
        } else {
            debugfs = false;
        }

        // We had access to debugfs for inducing the symbol type and we didn't
        // find anything. The symbol isn't traceable.
        if debugfs {
            bail!("Symbol {} does not exist or isn't traceable", name);
        }

        // We couldn't induce the type with certainty, fallback to a
        // non-foolproof logic.

        // At least check the symbol is in the kallsyms file. If the target
        // contains a ':' we assume it's a tracepoint (group:target).
        if inspector()?
            .kernel
            .get_symbol_addr(&match name.split_once(':') {
                Some((_, tp_name)) => format!("__tracepoint_{tp_name}"),
                _ => name.to_string(),
            })
            .is_err()
        {
            bail!("Symbol {} does not exist or isn't traceable", name);
        }

        Self::from_name_no_inspect(name).check()
    }

    /// Create a new symbol given its name without inspecting the current
    /// kernel. Result is non-foolprool but always returns a Symbol.
    pub(crate) fn from_name_no_inspect(name: &str) -> Symbol {
        match name.split_once(':') {
            Some(_) => Symbol::Event(name.to_string()),
            None => match name.strip_prefix("__tracepoint_") {
                Some(name) => Symbol::Event(name.to_string()),
                None => Symbol::Func(name.to_string()),
            },
        }
    }

    /// Create a new symbol given its address. We'll try hard to induce its
    /// type, using different techniques depending on what is available.
    pub(crate) fn from_addr(addr: u64) -> Result<Symbol> {
        // We're retrieving the symbol name from kallsyms. If this succeed, we
        // know it's a valid kernel symbol, but that doesn't mean it will map
        // 1:1 to a traceable one. Also we can't directly use the type detection
        // as we won't have a group:name format for events for example.
        let target = inspector()?.kernel.get_symbol_name(addr)?;

        // Check if the symbol is a tracepoint.
        let name = match target.strip_prefix("__tracepoint_") {
            Some(strip) => {
                match inspector()?.kernel.matching_events(&format!("*:{strip}")) {
                    Ok(mut events) if events.len() == 1 => events.pop().unwrap(),
                    _ => {
                        // Not much we can do, we know it's a valid one. Let's
                        // still return an object.
                        return Ok(Symbol::Event(format!("unknow:{strip}")));
                    }
                }
            }
            None => target.to_string(),
        };

        Self::from_name(&name)
    }

    /// Get the symbol name.
    ///
    /// E.g. for `kfree_skb`. If the Probe represents the:
    /// - event: `skb:kfree_skb`.
    /// - function: `kfree_skb`.
    pub(crate) fn name(&self) -> String {
        match self {
            Symbol::Func(name) => name.clone(),
            Symbol::Event(name) => name.clone(),
        }
    }

    /// Get the symbol attach name, used as a target for probing it.
    ///
    /// E.g. for `kfree_skb`. If the Probe represents the:
    /// - event: `kfree_skb`.
    /// - function: `kfree_skb`.
    pub(crate) fn attach_name(&self) -> String {
        match self {
            Symbol::Func(name) => name.clone(),
            Symbol::Event(name) => {
                // Unwrap as we checked this will always succeed when dealing
                // with a event, when creating the object.
                let (_, tgt) = name.split_once(':').unwrap();
                tgt.to_string()
            }
        }
    }

    /// Get the symbol name corresponding to its address.
    ///
    /// E.g. for `kfree_skb`. If the Probe represents the:
    /// - event: `__tracepoint_kfree_skb`.
    /// - function: `kfree_skb`.
    pub(crate) fn addr_name(&self) -> String {
        match self {
            Symbol::Func(name) => name.clone(),
            Symbol::Event(_) => {
                // We only support tracepoint events.
                format!("__tracepoint_{}", self.attach_name())
            }
        }
    }

    /// Get the symbol name use for its type definition.
    ///
    /// E.g. for `kfree_skb`. If the Probe represents the:
    /// - event: `btf_trace_kfree_skb`.
    /// - function: `kfree_skb`.
    pub(crate) fn typedef_name(&self) -> String {
        match self {
            Symbol::Func(name) => name.clone(),
            Symbol::Event(_) => {
                // We only support tracepoint events.
                //
                // Events need to access a symbol derived from TP_PROTO(), named
                // "btf_trace_<func>".
                format!("btf_trace_{}", self.attach_name())
            }
        }
    }

    /// Get the symbol address.
    pub(crate) fn addr(&self) -> Result<u64> {
        inspector()?.kernel.get_symbol_addr(&self.addr_name())
    }

    /// Get the symbol arguments number.
    pub(crate) fn nargs(&self) -> Result<u32> {
        inspector()?.kernel.function_nargs(self)
    }

    /// Get a parameter offset given its type, if found. Can be used to check a
    /// function has a given parameter by using:
    /// `function_parameter_offset()?.is_some()`.
    pub(crate) fn parameter_offset(&self, parameter_type: &str) -> Result<Option<u32>> {
        inspector()?.kernel.parameter_offset(self, parameter_type)
    }
}

/// Allow nice formatting when using a symbol in a log message.
///
/// E.g. for `kfree_skb`. If the Probe represents the:
/// - event: `skb:kfree_skb`.
/// - function: `kfree_skb`.
impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

pub(crate) fn matching_events_to_symbols(target: &str) -> Result<Vec<Symbol>> {
    let symbols = inspector()?
        .kernel
        .matching_events(target)?
        .iter()
        .filter_map(|t| Symbol::from_name(t).ok())
        .collect::<Vec<Symbol>>();

    if symbols.is_empty() {
        bail!("Could not find a tracepoint matching '{target}'");
    }

    Ok(symbols)
}

pub(crate) fn matching_functions_to_symbols(target: &str) -> Result<Vec<Symbol>> {
    let inspector = inspector()?;
    let symbols = inspector
        .kernel
        .matching_functions(target)?
        .iter()
        .filter_map(|t| Symbol::from_name(t).ok())
        .collect::<Vec<Symbol>>();

    if symbols.is_empty() {
        bail!("Could not find a traceable function matching '{target}'");
    }

    Ok(symbols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_name() {
        // First test an event.
        let symbol = Symbol::from_name("skb:kfree_skb").unwrap();
        assert!(symbol.attach_name() == "kfree_skb");
        assert!(symbol.addr_name() == "__tracepoint_kfree_skb");
        assert!(symbol.typedef_name() == "btf_trace_kfree_skb");
        assert!(symbol.nargs().unwrap() == 3);
        assert!(symbol.parameter_offset("struct sk_buff *").unwrap() == Some(0));
        assert!(symbol.parameter_offset("enum skb_drop_reason").unwrap() == Some(2));
        assert!(symbol
            .parameter_offset("struct net_device *")
            .unwrap()
            .is_none());

        // Then a function.
        let symbol = Symbol::from_name("kfree_skb_reason").unwrap();
        assert!(symbol.attach_name() == "kfree_skb_reason");
        assert!(symbol.addr_name() == "kfree_skb_reason");
        assert!(symbol.typedef_name() == "kfree_skb_reason");
        assert!(symbol.nargs().unwrap() == 2);
        assert!(symbol.parameter_offset("struct sk_buff *").unwrap() == Some(0));
        assert!(symbol.parameter_offset("enum skb_drop_reason").unwrap() == Some(1));
        assert!(symbol
            .parameter_offset("struct net_device *")
            .unwrap()
            .is_none());
    }

    #[test]
    fn from_addr() {
        // From an address (is an event).
        let symbol = Symbol::from_addr(0xffffffff9b2e5480).unwrap();
        assert!(symbol.attach_name() == "kfree_skb");
        assert!(symbol.addr_name() == "__tracepoint_kfree_skb");
        assert!(symbol.typedef_name() == "btf_trace_kfree_skb");
        assert!(symbol.nargs().unwrap() == 3);
        assert!(symbol.parameter_offset("struct sk_buff *").unwrap() == Some(0));
        assert!(symbol.parameter_offset("enum skb_drop_reason").unwrap() == Some(2));
        assert!(symbol
            .parameter_offset("struct net_device *")
            .unwrap()
            .is_none());

        // From an address (is a function).
        let symbol = Symbol::from_addr(0xffffffff99d1ddf0).unwrap();
        assert!(symbol.attach_name() == "kfree_skb_reason");
        assert!(symbol.addr_name() == "kfree_skb_reason");
        assert!(symbol.typedef_name() == "kfree_skb_reason");
        assert!(symbol.nargs().unwrap() == 2);
        assert!(symbol.parameter_offset("struct sk_buff *").unwrap() == Some(0));
        assert!(symbol.parameter_offset("enum skb_drop_reason").unwrap() == Some(1));
        assert!(symbol
            .parameter_offset("struct net_device *")
            .unwrap()
            .is_none());

        // Try two invalid address.
        assert!(Symbol::from_addr(0xffffffff9b2e5480 + 1).is_err());
        assert!(Symbol::from_addr(0xffffffff99d1ddf0 + 1).is_err());
    }
}
