use std::{collections::HashSet, fs};

use anyhow::{anyhow, bail, Result};
use bimap::BiHashMap;
use btf_rs::{Btf, Type};
use log::warn;
use once_cell::sync::OnceCell;

use super::Symbol;

static INSPECTOR: OnceCell<Inspector> = OnceCell::new();

macro_rules! get_inspector {
    () => {
        INSPECTOR.get_or_try_init(|| Inspector::new())
    };
}

/// Provides helpers to inspect probe related information in the kernel. Used as
/// a singleton.
pub(crate) struct Inspector {
    btf: Btf,
    /// Symbols bi-directional map (addr<>name).
    symbols: BiHashMap<u64, String>,
    /// Set of traceable events (e.g. tracepoints).
    traceable_events: Option<HashSet<String>>,
    /// Set of traceable functions (e.g. kprobes).
    traceable_funcs: Option<HashSet<String>>,
}

impl Inspector {
    fn new() -> Result<Inspector> {
        let (btf_file, symbols_file, events_file, funcs_file) = match cfg!(test) {
            false => (
                "/sys/kernel/btf/vmlinux",
                "/proc/kallsyms",
                "/sys/kernel/debug/tracing/available_events",
                "/sys/kernel/debug/tracing/available_filter_functions",
            ),
            true => (
                "test_data/vmlinux",
                "test_data/kallsyms",
                "test_data/available_events",
                "test_data/available_filter_functions",
            ),
        };

        // First parse the symbol file.
        let mut symbols = BiHashMap::new();
        for line in fs::read_to_string(symbols_file)?.lines() {
            let data: Vec<&str> = line.split(' ').collect();
            if data.len() < 3 {
                bail!("Invalid kallsyms line: {}", line);
            }

            let symbol: &str = data[2]
                .split('\t')
                .next()
                .ok_or_else(|| anyhow!("Couldn't get symbol name for {}", data[0]))?;

            symbols.insert(u64::from_str_radix(data[0], 16)?, String::from(symbol));
        }

        let inspector = Inspector {
            btf: Btf::from_file(btf_file)?,
            symbols,
            // Not all events we'll get from BTF/kallsyms are traceable. Use the
            // following, when available, to narrow down our checks.
            traceable_events: Self::file_to_hashset(events_file),
            // Not all functions we'll get from BTF/kallsyms are traceable. Use
            // the following, when available, to narrow down our checks.
            traceable_funcs: Self::file_to_hashset(funcs_file),
        };

        if inspector.traceable_funcs.is_none() || inspector.traceable_events.is_none() {
            warn!(
                "Consider mounting debugfs to /sys/kernel/debug to better filter available probes"
            );
        }

        Ok(inspector)
    }

    /// Convert a file containing a list of str (one per line) into a HashSet.
    /// Returns None if the file can't be read.
    fn file_to_hashset(target: &str) -> Option<HashSet<String>> {
        if let Ok(file) = fs::read_to_string(target) {
            let mut set = HashSet::new();
            for line in file.lines() {
                set.insert(line.to_string());
            }

            return Some(set);
        }
        None
    }
}

/// Return a symbol name given its address, if a relationship is found.
pub(super) fn get_symbol_name(addr: u64) -> Result<String> {
    Ok(get_inspector!()?
        .symbols
        .get_by_left(&addr)
        .ok_or_else(|| anyhow!("Can't get symbol name for {}", addr))?
        .clone())
}

/// Return a symbol address given its name, if a relationship is found.
pub(super) fn get_symbol_addr(name: &str) -> Result<u64> {
    Ok(*get_inspector!()?
        .symbols
        .get_by_right(name)
        .ok_or_else(|| anyhow!("Can't get symbol address for {}", name))?)
}

/// Given an address, try to find the nearest symbol, if any.
#[allow(dead_code)] // FIXME
pub(super) fn find_nearest_symbol(target: u64) -> Result<u64> {
    let (mut nearest, mut best_score) = (0, std::u64::MAX);

    for addr in get_inspector!()?.symbols.left_values() {
        // The target address has to be greater or equal to a symbol address to
        // be considered near it (and part of it).
        if target < *addr {
            continue;
        }

        let score = target.abs_diff(*addr);
        if score < best_score {
            nearest = *addr;
            best_score = score;

            // Exact match; can't do better than that.
            if score == 0 {
                break;
            }
        }
    }

    if best_score == std::u64::MAX {
        bail!("Can't get a symbol near {}", target);
    }

    Ok(nearest)
}

/// Check if an event is traceable. Return Ok(None) if we can't know.
pub(super) fn is_event_traceable(name: &str) -> Result<Option<bool>> {
    let set = &get_inspector!()?.traceable_events;

    // If we can't check further, we don't know if the event is traceable and we
    // return None.
    if set.is_none() {
        return Ok(None);
    }

    // Unwrap as we checked above we have a set of valid events.
    Ok(Some(set.as_ref().unwrap().get(name).is_some()))
}

/// Check if an event is traceable. Return Ok(None) if we can't know.
pub(super) fn is_function_traceable(name: &str) -> Result<Option<bool>> {
    let set = &get_inspector!()?.traceable_funcs;

    // If we can't check further, we don't know if the function is traceable and
    // we return None.
    if set.is_none() {
        return Ok(None);
    }

    // Unwrap as we checked above we have a set of valid functions.
    Ok(Some(set.as_ref().unwrap().get(name).is_some()))
}

/// Given an event name (without the group part), try to find a corresponding
/// event (with the group part) and return the full name.
///
/// `assert!(find_matching_event("kfree_skb").unwrap() == Some("skb:kfree_skb"));`
pub(super) fn find_matching_event(name: &str) -> Result<Option<String>> {
    let set = &get_inspector!()?.traceable_events;

    // If we can't check further, return None.
    if set.is_none() {
        return Ok(None);
    }

    let suffix = format!(":{}", name);

    // Unwrap as we checked above we have a set of valid events.
    for event in set.as_ref().unwrap().iter() {
        if event.ends_with(&suffix) {
            return Ok(Some(event.clone()));
        }
    }

    Ok(None)
}

/// Get a parameter offset given a kernel function, if  any. Can be used to
/// check a function has a given parameter by using:
/// `parameter_offset()?.is_some()`
pub(super) fn parameter_offset(symbol: &Symbol, parameter_type: &str) -> Result<Option<u32>> {
    // Events have a void* pointing to the data as their first argument, which
    // does not end up in their context. We have to skip it. See
    // include/trace/bpf_probe.h in the __DEFINE_EVENT definition.
    let fix = match symbol {
        Symbol::Event(_) => 1,
        _ => 0,
    };

    let proto = get_function_prototype(symbol)?;
    for (offset, param) in proto.parameters.iter().enumerate() {
        if is_param_type(param, parameter_type)? {
            if offset < fix {
                continue;
            }
            return Ok(Some((offset - fix) as u32));
        }
    }
    Ok(None)
}

/// Get a function number of arguments.
pub(super) fn function_nargs(symbol: &Symbol) -> Result<u32> {
    // Events have a void* pointing to the data as their first argument, which
    // does not end up in their context. We have to skip it. See
    // include/trace/bpf_probe.h in the __DEFINE_EVENT definition.
    let fix = match symbol {
        Symbol::Event(_) => 1,
        _ => 0,
    };

    let proto = get_function_prototype(symbol)?;
    Ok((proto.parameters.len() - fix) as u32)
}

fn get_function_prototype(symbol: &Symbol) -> Result<btf_rs::FuncProto> {
    let btf = &get_inspector!()?.btf;
    let target = symbol.typedef_name();
    // Some probe types might need to change the target format.
    Ok(match symbol {
        Symbol::Func(_) => {
            // Functions are using directly the target function definition, no
            // change to make to the target format and the prototype resolution
            // is straightforward: Func -> FuncProto.
            let func = match btf.resolve_type_by_name(&target)? {
                Type::Func(func) => func,
                _ => bail!("{} is not a function", target),
            };

            match btf.resolve_chained_type(&func)? {
                Type::FuncProto(proto) => proto,
                _ => bail!("Function {} does not have a prototype", target),
            }
        }
        Symbol::Event(_) => {
            // The prototype resolution for events is:
            // Typedef -> Ptr -> FuncProto.
            let func = match btf.resolve_type_by_name(&target)? {
                Type::Typedef(func) => func,
                _ => bail!("{} is not a typedef", target),
            };

            let ptr = match btf.resolve_chained_type(&func)? {
                Type::Ptr(ptr) => ptr,
                _ => bail!("{} typedef does not point to a ptr", target),
            };

            match btf.resolve_chained_type(&ptr)? {
                Type::FuncProto(proto) => proto,
                _ => bail!("Function {} does not have a prototype", target),
            }
        }
    })
}

fn is_param_type(param: &btf_rs::Parameter, r#type: &str) -> Result<bool> {
    let btf = &get_inspector!()?.btf;

    let mut resolved = btf.resolve_chained_type(param)?;
    let mut full_name = String::new();

    // First, traverse the type definition until we find the actual type.
    // Only support valid resolve_chained_type calls and exclude function
    // pointers, static/global variables and especially typedef as we don't
    // want to traverse its full definition!
    let mut is_pointer = false;
    loop {
        resolved = match resolved {
            Type::Ptr(t) => {
                is_pointer = true;
                btf.resolve_chained_type(&t)?
            }
            Type::Volatile(t) => btf.resolve_chained_type(&t)?,
            Type::Const(t) => btf.resolve_chained_type(&t)?,
            Type::Array(_) => bail!("Arrays are not supported at the moment"),
            _ => break,
        }
    }

    // Then resolve the type name.
    let type_name = match resolved {
        Type::Int(t) => btf.resolve_name(&t)?,
        Type::Struct(t) => format!("struct {}", btf.resolve_name(&t)?),
        Type::Union(t) => format!("union {}", btf.resolve_name(&t)?),
        Type::Enum(t) => format!("enum {}", btf.resolve_name(&t)?),
        Type::Typedef(t) => btf.resolve_name(&t)?,
        Type::Float(t) => btf.resolve_name(&t)?,
        Type::Enum64(t) => format!("enum {}", btf.resolve_name(&t)?),
        _ => return Ok(false),
    };
    full_name.push_str(type_name.as_str());

    // Set the pointer information C style.
    if is_pointer {
        full_name.push_str(" *");
    }

    // We do not get the symbol name; useless and not always there (e.g.
    // raw tracepoints).

    Ok(r#type == full_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_name() {
        assert!(get_symbol_name(0xffffffff95617530).unwrap() == "consume_skb");
    }

    #[test]
    fn symbol_addr() {
        assert!(get_symbol_addr("consume_skb").unwrap() == 0xffffffff95617530);
    }

    #[test]
    fn test_bijection() {
        let symbol = "consume_skb";
        let addr = get_symbol_addr(symbol).unwrap();
        let name = get_symbol_name(addr).unwrap();

        assert!(symbol == name);
    }

    #[test]
    fn nearest_symbol() {
        let addr = get_symbol_addr("consume_skb").unwrap();

        assert!(find_nearest_symbol(addr + 1).unwrap() == addr);
        assert!(find_nearest_symbol(addr).unwrap() == addr);
        assert!(find_nearest_symbol(addr - 1).unwrap() != addr);
    }

    #[test]
    fn parameter_offset() {
        assert!(
            super::parameter_offset(
                &Symbol::Func("kfree_skb_reason".to_string()),
                "struct sk_buff *"
            )
            .unwrap()
                == Some(0)
        );

        assert!(
            super::parameter_offset(
                &Symbol::Func("kfree_skb_reason".to_string()),
                "struct sk_buff"
            )
            .unwrap()
                == None
        );

        assert!(
            super::parameter_offset(
                &Symbol::Event("skb:kfree_skb".to_string()),
                "struct sk_buff *"
            )
            .unwrap()
                == Some(0)
        );

        assert!(
            super::parameter_offset(
                &Symbol::Event("skb:kfree_skb".to_string()),
                "enum skb_drop_reason"
            )
            .unwrap()
                == Some(2)
        );
    }
}
