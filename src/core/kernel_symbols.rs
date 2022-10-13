//! # Kernel symbols
//!
//! Interface to query the kernel symbol addresses / name relashinship, in both
//! ways. It does so by parsing /proc/kallsyms and by using a singleton
//! initialized on-demand.

#![allow(dead_code)]

use anyhow::{anyhow, bail, Result};
use bimap::BiHashMap;
use once_cell::sync::OnceCell;
use std::fs;

/// Kernel symbols bidirectional map. To retrieve it, please use:
/// ```
/// map.insert(u64::from_str_radix(data[0], 16)?, String::from(symbol));
/// ```
static SYMBOLS: OnceCell<BiHashMap<u64, String>> = OnceCell::new();

/// Return a reference to the symbol map and initialize it on first access. To
/// set the initial values, /proc/kallsyms is parsed as it contains the kernel
/// symbol addr<>name relationships.
macro_rules! get_symbols {
    () => {
        SYMBOLS.get_or_try_init(|| {
            let file = fs::read_to_string("/proc/kallsyms")?;
            let mut map = BiHashMap::new();

            for line in file.lines() {
                let data: Vec<&str> = line.split(' ').collect();
                if data.len() < 3 {
                    bail!("Invalid kallsyms line: {}", line);
                }

                let symbol: &str = data[2]
                    .split('\t')
                    .next()
                    .ok_or_else(|| anyhow!("Couldn't get symbol name for {}", data[0]))?;

                map.insert(u64::from_str_radix(data[0], 16)?, String::from(symbol));
            }

            Ok(map)
        })
    };
}

/// Return a symbol name given its address, if a relationship is found.
pub(crate) fn get_symbol_name(addr: u64) -> Result<String> {
    Ok(get_symbols!()?
        .get_by_left(&addr)
        .ok_or_else(|| anyhow!("Can't get symbol name for {}", addr))?
        .clone())
}

/// Return a symbol address given its name, if a relationship is found.
pub(crate) fn get_symbol_addr(name: &str) -> Result<u64> {
    Ok(*get_symbols!()?
        .get_by_right(name)
        .ok_or_else(|| anyhow!("Can't get symbol address for {}", name))?)
}

/// Given an address, try to find the nearest symbol, if any.
pub(crate) fn find_nearest_symbol(target: u64) -> Result<u64> {
    let (mut nearest, mut best_score) = (0, std::u64::MAX);
    let symbols = get_symbols!()?;

    for addr in symbols.left_values() {
        // The target address has to be greater or equal to a symbol address to
        // be considered near it (and part of it).
        if target < *addr {
            continue;
        }

        let score = target.abs_diff(*addr);
        if score < best_score {
            nearest = *addr;
            best_score = score;
        }
    }

    if best_score == std::u64::MAX {
        bail!("Can't get a symbol near {}", target);
    }

    Ok(nearest)
}
