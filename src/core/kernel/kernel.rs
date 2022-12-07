use std::fmt;

use anyhow::{bail, Result};

use super::{inspect, symbols};
use crate::core::probe::kernel::ProbeType;

/// Kernel symbol representation. Only supports traceable symbols: events and
/// functions.
pub(crate) struct Symbol {
    r#type: SymbolType,
    name: String,
}

impl Symbol {
    fn new(r#type: SymbolType, name: &str) -> Symbol {
        Symbol {
            r#type,
            name: name.to_string(),
        }
    }

    /// Create a new symbol given its name. We'll try hard to induce its type,
    /// using different techniques depending on what is available.
    pub(crate) fn from_name(name: &str) -> Result<Symbol> {
        let mut debugfs = false;

        // First try to see if the symbol is a traceable event.
        if let Some(traceable) = inspect::is_event_traceable(name)? {
            debugfs = true;
            if traceable {
                return Ok(Symbol::new(SymbolType::Event, name));
            }
        }

        // Then try to see if it's a traceable function.
        if let Some(traceable) = inspect::is_function_traceable(name)? {
            if traceable {
                return Ok(Symbol::new(SymbolType::Func, name));
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

        // Events have a group:target format. Let's see if we match something.
        if let Some((_, tp_name)) = name.split_once(':') {
            // We might have an event, let's see if we can find a tracepoint
            // symbol.
            let tp_name = format!("__tracepoint_{}", tp_name);
            if symbols::get_symbol_addr(&tp_name).is_ok() {
                return Ok(Symbol::new(SymbolType::Event, name));
            }
        }

        // Traceable functions should be in the kallsyms file. Let's see if we
        // find a match.
        if symbols::get_symbol_addr(name).is_ok() {
            return Ok(Symbol::new(SymbolType::Func, name));
        }

        bail!("Symbol {} does not exist or isn't traceable", name);
    }

    /// Create a new symbol given its address. We'll try hard to induce its
    /// type, using different techniques depending on what is available.
    pub(crate) fn from_addr(addr: u64) -> Result<Symbol> {
        // We're retrieving the symbol name from kallsyms. If this succeed, we
        // know it's a valid kernel symbol, but that doesn't mean it will map
        // 1:1 to a traceable one. Also we can't directly use the type detection
        // as we won't have a group:name format for events for example.
        let target = symbols::get_symbol_name(addr)?;

        // Check if the symbol is a tracepoint.
        let name = match target.strip_prefix("__tracepoint_") {
            Some(strip) => {
                match inspect::find_matching_event(strip)? {
                    Some(event) => event,
                    // Not much we can do, let's try to see if we can find the
                    // function itself, but it might not be traceable.
                    None => strip.to_string(),
                }
            }
            None => target.to_string(),
        };

        Ok(match Self::from_name(&name) {
            Ok(symbol) => symbol,
            // We still weren't able to find the symbol, but we know it's a
            // valid one. Let's still return an object, which might be limited.
            Err(_) => Symbol::new(SymbolType::Func, &name),
        })
    }

    /// Get the symbol function name.
    ///
    /// E.g. for `kfree_skb`. If the Probe represents the:
    /// - event: `kfree_skb`.
    /// - function: `kfree_skb`.
    pub(crate) fn func_name(&self) -> String {
        match self.r#type {
            SymbolType::Func => self.name.clone(),
            SymbolType::Event => {
                // Unwrap as we checked this will always succeed when dealing
                // with a event, when creating the object.
                let (_, tgt) = self.name.split_once(':').unwrap();
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
        match self.r#type {
            SymbolType::Func => self.name.clone(),
            SymbolType::Event => {
                format!("__tracepoint_{}", self.func_name())
            }
        }
    }

    /// Get the symbol name use for its type definition.
    ///
    /// E.g. for `kfree_skb`. If the Probe represents the:
    /// - event: `btf_trace_kfree_skb`.
    /// - function: `kfree_skb`.
    pub(crate) fn typedef_name(&self) -> String {
        match self.r#type {
            SymbolType::Func => self.name.clone(),
            // Events need to access a symbol derived from TP_PROTO(), named
            // "btf_trace_<func>".
            SymbolType::Event => {
                format!("btf_trace_{}", self.func_name())
            }
        }
    }

    /// Get the symbol address.
    pub(crate) fn addr(&self) -> Result<u64> {
        symbols::get_symbol_addr(&self.addr_name())
    }

    /// Get the symbol arguments number.
    pub(crate) fn nargs(&self) -> Result<u32> {
        inspect::function_nargs(self.r#type, &self.typedef_name())
    }

    /// Get a parameter offset given its type, if found. Can be used to check a
    /// function has a given parameter by using:
    /// `function_parameter_offset()?.is_some()`.
    pub(crate) fn parameter_offset(&self, parameter_type: &str) -> Result<Option<u32>> {
        inspect::parameter_offset(self.r#type, &self.typedef_name(), parameter_type)
    }

    /// Check if the symbol can be probed using a specific probe type.
    pub(crate) fn can_probe(&self, probe_type: ProbeType) -> bool {
        match self.r#type {
            SymbolType::Event => {
                if probe_type == ProbeType::RawTracepoint {
                    return true;
                }
            }
            SymbolType::Func => {
                if probe_type == ProbeType::Kprobe {
                    return true;
                }
            }
        }
        false
    }
}

/// Only allow to access the symbol name using the Display trait as this should
/// be used for reporting things about the symbol (events, logs, etc) but not
/// directly used in other APIs.
///
/// E.g. for `kfree_skb`. If the Probe represents the:
/// - event: `skb:kfree_skb`.
/// - function: `kfree_skb`.
impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(Copy, Clone)]
pub(super) enum SymbolType {
    Event,
    Func,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_name() {
        // First test an event.
        let symbol = Symbol::from_name("skb:kfree_skb").unwrap();
        assert!(symbol.func_name() == "kfree_skb");
        assert!(symbol.addr_name() == "__tracepoint_kfree_skb");
        assert!(symbol.typedef_name() == "btf_trace_kfree_skb");
        assert!(symbol.nargs().unwrap() == 3);
        assert!(symbol.parameter_offset("struct sk_buff *").unwrap() == Some(0));
        assert!(symbol.parameter_offset("enum skb_drop_reason").unwrap() == Some(2));
        assert!(symbol.parameter_offset("struct net_device *").unwrap() == None);

        // Then a function.
        let symbol = Symbol::from_name("kfree_skb_reason").unwrap();
        assert!(symbol.func_name() == "kfree_skb_reason");
        assert!(symbol.addr_name() == "kfree_skb_reason");
        assert!(symbol.typedef_name() == "kfree_skb_reason");
        assert!(symbol.nargs().unwrap() == 2);
        assert!(symbol.parameter_offset("struct sk_buff *").unwrap() == Some(0));
        assert!(symbol.parameter_offset("enum skb_drop_reason").unwrap() == Some(1));
        assert!(symbol.parameter_offset("struct net_device *").unwrap() == None);
    }

    #[test]
    fn from_addr() {
        // From an address (is an event).
        let symbol = Symbol::from_addr(0xffffffff983c29a0).unwrap();
        assert!(symbol.func_name() == "kfree_skb");
        assert!(symbol.addr_name() == "__tracepoint_kfree_skb");
        assert!(symbol.typedef_name() == "btf_trace_kfree_skb");
        assert!(symbol.nargs().unwrap() == 3);
        assert!(symbol.parameter_offset("struct sk_buff *").unwrap() == Some(0));
        assert!(symbol.parameter_offset("enum skb_drop_reason").unwrap() == Some(2));
        assert!(symbol.parameter_offset("struct net_device *").unwrap() == None);

        // From an address (is a function).
        let symbol = Symbol::from_addr(0xffffffff95612980).unwrap();
        assert!(symbol.func_name() == "kfree_skb_reason");
        assert!(symbol.addr_name() == "kfree_skb_reason");
        assert!(symbol.typedef_name() == "kfree_skb_reason");
        assert!(symbol.nargs().unwrap() == 2);
        assert!(symbol.parameter_offset("struct sk_buff *").unwrap() == Some(0));
        assert!(symbol.parameter_offset("enum skb_drop_reason").unwrap() == Some(1));
        assert!(symbol.parameter_offset("struct net_device *").unwrap() == None);

        // Try two invalid address.
        assert!(Symbol::from_addr(0xffffffff983c29a0 + 1).is_err());
        assert!(Symbol::from_addr(0xffffffff95612980 + 1).is_err());
    }
}
