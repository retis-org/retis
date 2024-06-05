#![allow(dead_code)] // FIXME

use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    fs,
    io::Read,
    ops::Bound::{Included, Unbounded},
    path::{Path, PathBuf},
    str,
};

use anyhow::{anyhow, bail, Result};
use bimap::BiBTreeMap;
use flate2::bufread::GzDecoder;
use log::warn;
use regex::Regex;

use super::{btf::BtfInfo, kernel_version::KernelVersion, BASE_TEST_DIR};
use crate::core::kernel::Symbol;

/// Provides helpers to inspect probe related information in the kernel.
pub(crate) struct KernelInspector {
    /// Btf information.
    pub(crate) btf: BtfInfo,
    /// Symbols bi-directional map (addr<>name).
    symbols: BiBTreeMap<u64, String>,
    /// Set of traceable events (e.g. tracepoints).
    traceable_events: Option<HashSet<String>>,
    /// Set of traceable functions (e.g. kprobes).
    traceable_funcs: Option<HashSet<String>>,
    /// Kernel version, eg. "6.2.14-300" (Fedora) or "5.10.0-22" (Debian).
    version: KernelVersion,
    /// Map of all kernel config options and their values. Common values are
    /// "y", "m" and "n", but options can also be set to a string and some other
    /// types. All are stored as a String here.
    config: Option<HashMap<String, String>>,
    /// List of all loaded kernel modules. We do cache the result for now as
    /// it's quite unlikely modules we are interested in tracing will get loaded
    /// in the short time between Retis launch and collection starts. But that
    /// can be cnahged later on if needed.
    modules: Option<HashSet<String>>,
}

impl KernelInspector {
    pub(crate) fn from(kconf: Option<&PathBuf>) -> Result<KernelInspector> {
        let (symbols_file, events_file, funcs_file, modules_file) =
            match cfg!(test) || cfg!(feature = "benchmark") {
                false => (
                    "/proc/kallsyms".to_owned(),
                    "/sys/kernel/debug/tracing/available_events".to_owned(),
                    "/sys/kernel/debug/tracing/available_filter_functions".to_owned(),
                    "/proc/modules".to_owned(),
                ),
                true => (
                    BASE_TEST_DIR.to_owned() + "/test_data/kallsyms",
                    BASE_TEST_DIR.to_owned() + "/test_data/available_events",
                    BASE_TEST_DIR.to_owned() + "/test_data/available_filter_functions",
                    BASE_TEST_DIR.to_owned() + "/test_data/modules",
                ),
            };
        let btf = BtfInfo::new()?;

        // First parse the symbol file.
        let mut symbols = BiBTreeMap::new();
        // Lines have to be processed backward in order to overwrite
        // duplicate addresses and keep the first (which is the last
        // inserted in the common case involving module init
        // functions) instead of the last one.
        for line in fs::read_to_string(symbols_file)?.lines().rev() {
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

        // If all symbols have a 0-address, only the last one will be left in
        // the map after the above.
        if symbols.len() == 1 {
            bail!("Retis likely does not have the rights to read the symbol addresses from /proc/kallsyms.");
        }

        let version = KernelVersion::new()?;
        let config = Self::parse_kernel_config(&version.full, kconf)?;

        let inspector = KernelInspector {
            btf,
            symbols,
            // Not all events we'll get from BTF/kallsyms are traceable. Use the
            // following, when available, to narrow down our checks.
            traceable_events: Self::file_to_hashset(events_file),
            // Not all functions we'll get from BTF/kallsyms are traceable. Use
            // the following, when available, to narrow down our checks.
            traceable_funcs: Self::file_to_hashset(funcs_file),
            version,
            config,
            modules: Self::file_to_hashset(modules_file),
        };

        if inspector.traceable_funcs.is_none() || inspector.traceable_events.is_none() {
            warn!(
                "Could not access files in /sys/kernel/debug/tracing: consider mounting debugfs, if not a permissions issue"
            );
        }

        Ok(inspector)
    }

    /// Convert a file containing a list of str (one per line) into a HashSet.
    /// Returns None if the file can't be read.
    fn file_to_hashset<P>(target: P) -> Option<HashSet<String>>
    where
        P: AsRef<Path> + Display + Clone,
    {
        if let Ok(file) = fs::read_to_string(target.clone()) {
            let mut set = HashSet::new();
            for line in file.lines() {
                // functions might be formatted as "func_name [module]".
                match line.split(' ').next() {
                    Some(symbol) => {
                        set.insert(symbol.to_string());
                    }
                    None => {
                        warn!("Symbol list element has an unexpected format in {target}: {line}");
                    }
                }
            }

            return Some(set);
        }
        None
    }

    /// Parse the kernel configuration.
    fn parse_kernel_config(
        release: &str,
        kconf: Option<&PathBuf>,
    ) -> Result<Option<HashMap<String, String>>> {
        // If we have a user-defined kernel configuration file, use it.
        if let Some(kconf) = kconf {
            return Ok(Some(Self::parse_kernel_config_single(kconf).map_err(
                |e| anyhow!("Could not read {}: {e}", kconf.display()),
            )?));
        }

        // If not, try auto-detection.
        let paths = [
            "/proc/config.gz".to_string(),
            format!("/boot/config-{}", release),
            // CoreOS & friends.
            format!("/lib/modules/{}/config", release),
            // Toolbox on CoreOS & friends.
            format!("/run/host/usr/lib/modules/{}/config", release),
        ];
        for p in paths.iter() {
            if let Ok(kconf) = Self::parse_kernel_config_single(p) {
                return Ok(Some(kconf));
            }
        }

        warn!(
            "Could not parse kernel configuration from known paths: some checks won't be performed"
        );
        Ok(None)
    }

    /// Lower level helper to try parsing a single kernel configuration file.
    fn parse_kernel_config_single<P: AsRef<Path>>(file: P) -> Result<HashMap<String, String>> {
        let parse_kconfig = |file: &str| -> Result<HashMap<String, String>> {
            let mut map = HashMap::new();

            file.lines().try_for_each(|l| -> Result<()> {
                if l.starts_with("CONFIG_") {
                    let (cfg, val) = l
                        .split_once('=')
                        .ok_or_else(|| anyhow!("Could not parse the Kconfig option"))?;

                    // Handle string values nicely.
                    let val = val.trim_start_matches('"').trim_end_matches('"');

                    map.insert(cfg.to_string(), val.to_string());
                } else if l.starts_with("# CONFIG_") {
                    // Unwrap as we just made sure this would succeed.
                    let (cfg, _) = l
                        .strip_prefix("# ")
                        .unwrap()
                        .split_once(' ')
                        .ok_or_else(|| anyhow!("Could not parse the Kconfig option"))?;
                    map.insert(cfg.to_string(), 'n'.to_string());
                }
                Ok(())
            })?;

            Ok(map)
        };

        let bytes = fs::read(file)?;

        // Check gzip magic value.
        if bytes[0] == 0x1f && bytes[1] == 0x8b {
            let mut decoder = GzDecoder::new(&bytes[..]);
            let mut content = String::new();
            decoder.read_to_string(&mut content)?;

            parse_kconfig(&content)
        } else {
            parse_kconfig(str::from_utf8(&bytes)?)
        }
    }

    /// Return the running kernel version.
    pub(crate) fn version(&self) -> &KernelVersion {
        &self.version
    }

    /// The following retrieves a kernel configuration option value, if found.
    /// Users might want to catch the error and make silence it if their check
    /// is non-mandatory.
    pub(crate) fn get_config_option(&self, option: &str) -> Result<Option<&str>> {
        if self.config.is_none() {
            bail!("Could not query the kernel configuration");
        }

        // Unwrap as we just checked earlier this could not fail.
        Ok(self
            .config
            .as_ref()
            .unwrap()
            .get(&option.to_string())
            .map(|x| x.as_str()))
    }

    /// Check if a kernel module is loaded.
    pub(crate) fn is_module_loaded(&self, module: &str) -> Option<bool> {
        self.modules
            .as_ref()
            .map(|modules| modules.contains(&module.to_string()))
    }

    /// Return a symbol name given its address, if a relationship is found.
    pub(crate) fn get_symbol_name(&self, addr: u64) -> Result<String> {
        Ok(self
            .symbols
            .get_by_left(&addr)
            .ok_or_else(|| anyhow!("Can't get symbol name for {}", addr))?
            .clone())
    }

    /// Return a symbol address given its name, if a relationship is found.
    pub(crate) fn get_symbol_addr(&self, name: &str) -> Result<u64> {
        Ok(*self
            .symbols
            .get_by_right(name)
            .ok_or_else(|| anyhow!("Can't get symbol address for {}", name))?)
    }

    /// Given an address, try to find the nearest symbol, if any.
    pub(crate) fn find_nearest_symbol(&self, target: u64) -> Result<u64> {
        let nearest = self
            .symbols
            .left_range((Unbounded, Included(&target)))
            .next_back();

        match nearest {
            Some(symbol) => Ok(*symbol.0),
            None => bail!("Can't get a symbol near {}", target),
        }
    }

    /// Check if an event is traceable. Return None if we can't know.
    pub(crate) fn is_event_traceable(&self, name: &str) -> Option<bool> {
        let set = &self.traceable_events;

        // If we can't check further, we don't know if the event is traceable and we
        // return None.
        if set.is_none() {
            return None;
        }

        // Unwrap as we checked above we have a set of valid events.
        Some(set.as_ref().unwrap().get(name).is_some())
    }

    /// Check if an event is traceable. Return None if we can't know.
    pub(crate) fn is_function_traceable(&self, name: &str) -> Option<bool> {
        let set = &self.traceable_funcs;

        // If we can't check further, we don't know if the function is traceable and
        // we return None.
        if set.is_none() {
            return None;
        }

        // Unwrap as we checked above we have a set of valid functions.
        Some(set.as_ref().unwrap().get(name).is_some())
    }

    /// Get a parameter offset given a kernel function, if  any. Can be used to
    /// check a function has a given parameter by using:
    /// `inspector()?.parameter_offset()?.is_some()`
    pub(crate) fn parameter_offset(
        &self,
        symbol: &Symbol,
        parameter_type: &str,
    ) -> Result<Option<u32>> {
        self.btf.parameter_offset(symbol, parameter_type)
    }

    /// Get a function's number of arguments.
    pub(crate) fn function_nargs(&self, symbol: &Symbol) -> Result<u32> {
        self.btf.function_nargs(symbol)
    }

    /// Given an address, gets the name and the offset of the nearest symbol, if any.
    pub(crate) fn get_name_offt_from_addr_near(&self, addr: u64) -> Result<(String, u64)> {
        let sym_addr = self.find_nearest_symbol(addr)?;
        Ok((
            self.get_symbol_name(sym_addr)?,
            u64::checked_sub(addr, sym_addr)
                .ok_or_else(|| anyhow!("failed to get symbol offset"))?,
        ))
    }

    fn match_in_set(set: &HashSet<String>, target: &str) -> Result<Vec<String>> {
        let target = format!("^{}$", target.replace('*', ".*"));
        let re = Regex::new(&target)?;

        // Unwrap as we checked above we have a set of valid events.
        Ok(set.iter().filter(|f| re.is_match(f)).cloned().collect())
    }

    /// Find events matching a given pattern. So far only wildcards (*) are
    /// supported, e.g. "skb:*", "*:kfree_skb" or "*skb*".
    pub(crate) fn matching_events(&self, target: &str) -> Result<Vec<String>> {
        Self::match_in_set(
            self
                .traceable_events
                .as_ref()
                .ok_or_else(|| anyhow!("Could not get matching events as Retis can't access files in /sys/kernel/debug/tracing"))?,
                target
        )
    }

    /// Find functions matching a given pattern. So far only wildcards (*) are
    /// supported, e.g. "tcp_v6_*".
    pub(crate) fn matching_functions(&self, target: &str) -> Result<Vec<String>> {
        Self::match_in_set(
            self
                .traceable_funcs
                .as_ref()
                .ok_or_else(|| anyhow!("Could not get matching functions as Retis can't access files in /sys/kernel/debug/tracing"))?,
                target
        )
    }
}

#[cfg(test)]
mod tests {
    use super::KernelInspector;
    use std::path::PathBuf;

    fn inspector() -> KernelInspector {
        let kconf = PathBuf::from("test_data/config-6.3.0-0.rc7.56.fc39.x86_64");
        super::KernelInspector::from(Some(&kconf)).unwrap()
    }

    #[test]
    fn inspector_init() {
        let kconf = PathBuf::from("test_data/config-6.3.0-0.rc7.56.fc39.x86_64");
        assert!(super::KernelInspector::from(Some(&kconf)).is_ok());
    }

    #[test]
    fn symbol_name() {
        assert!(inspector().get_symbol_name(0xffffffff99d1da80).unwrap() == "consume_skb");
    }

    #[test]
    fn symbol_addr() {
        assert!(inspector().get_symbol_addr("consume_skb").unwrap() == 0xffffffff99d1da80);
    }

    #[test]
    fn test_bijection() {
        let symbol = "consume_skb";
        let addr = inspector().get_symbol_addr(symbol).unwrap();
        let name = inspector().get_symbol_name(addr).unwrap();

        assert!(symbol == name);
    }

    #[test]
    fn nearest_symbol() {
        let addr = inspector().get_symbol_addr("consume_skb").unwrap();

        assert!(inspector().find_nearest_symbol(addr + 1).unwrap() == addr);
        assert!(inspector().find_nearest_symbol(addr).unwrap() == addr);
        assert!(inspector().find_nearest_symbol(addr - 1).unwrap() != addr);
    }

    #[test]
    fn name_from_addr_near() {
        let mut sym_info = inspector()
            .get_name_offt_from_addr_near(0xffffffff99d1da80 + 1)
            .unwrap();

        assert_eq!(sym_info.0, "consume_skb");
        assert_eq!(sym_info.1, 0x1_u64);

        sym_info = inspector()
            .get_name_offt_from_addr_near(0xffffffff99d1da80 - 1)
            .unwrap();
        assert_ne!(sym_info.0, "consume_skb");

        sym_info = inspector()
            .get_name_offt_from_addr_near(0xffffffff99d1da80)
            .unwrap();
        assert_eq!(sym_info.0, "consume_skb");
        assert_eq!(sym_info.1, 0x0_u64);
    }

    #[test]
    fn kernel_config() {
        assert_eq!(
            inspector().get_config_option("CONFIG_VETH").unwrap(),
            Some("m")
        );
        assert_eq!(
            inspector().get_config_option("CONFIG_OPENVSWITCH").unwrap(),
            Some("m")
        );
        assert_eq!(inspector().get_config_option("CONFIG_FOO").unwrap(), None);
        assert_eq!(
            inspector().get_config_option("CONFIG_NETPOLL").unwrap(),
            Some("y")
        );
        assert_eq!(
            inspector()
                .get_config_option("CONFIG_DEFAULT_HOSTNAME")
                .unwrap(),
            Some("(none)")
        );
    }

    #[test]
    fn kernel_modules() {
        assert_eq!(inspector().is_module_loaded("zram"), Some(true));
        assert_eq!(inspector().is_module_loaded("openvswitch"), Some(false));
    }
}
