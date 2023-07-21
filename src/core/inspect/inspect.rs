#![allow(dead_code)] // FIXME

use std::{fs, path::PathBuf};

use anyhow::{bail, Result};
use once_cell::sync::OnceCell;

use super::kernel::KernelInspector;

static INSPECTOR: OnceCell<Inspector> = OnceCell::new();

/// Gets a reference on the inspector.
pub(crate) fn inspector() -> Result<&'static Inspector> {
    INSPECTOR.get_or_try_init(|| Inspector::from(None))
}

/// Initialize the inspector with custom parameters, fail is already
/// initialized.
pub(crate) fn init_inspector(kconf: &PathBuf) -> Result<()> {
    let inspector = Inspector::from(Some(kconf))?;
    if INSPECTOR.set(inspector).is_err() {
        bail!("Could not init inspector: was already initialized.");
    }
    Ok(())
}

/// Provides helpers to inspect various information about the system and the
/// kernel. Used as a singleton.
pub(crate) struct Inspector {
    /// Kernel part of the inspector.
    pub(crate) kernel: KernelInspector,
    /// OS id, eg. "fedora" or "debian". None if we couldn't get it.
    pub(crate) os_id: Option<String>,
    /// OS version, eg. "38" or "10". None if we couldn't get it.
    pub(crate) os_version: Option<String>,
}

impl Inspector {
    fn from(kconf: Option<&PathBuf>) -> Result<Inspector> {
        let (os_id, os_version) = Self::parse_os_info()?;

        Ok(Inspector {
            kernel: KernelInspector::from(kconf)?,
            os_id,
            os_version,
        })
    }
}

impl Inspector {
    /// Parse OS identifier to allow check what is the underlying system.
    ///
    /// Returns the system (id, version). Eg. ("fedora", "38").
    fn parse_os_info() -> Result<(Option<String>, Option<String>)> {
        let extract = |line: &str, prefix: &str, to: &mut Option<String>| {
            if let Some(val) = line.strip_prefix(prefix).map(|val| {
                val.trim_start_matches('"')
                    .trim_end_matches('"')
                    .to_string()
            }) {
                *to = Some(val);
            }
        };

        let mut id = None;
        let mut version = None;
        // https://www.freedesktop.org/software/systemd/man/os-release.html
        if let Ok(file) = fs::read_to_string(if !cfg!(test) {
            "/etc/os-release"
        } else {
            "test_data/os-release"
        }) {
            file.lines().for_each(|line| {
                extract(line, "ID=", &mut id);
                extract(line, "VERSION_ID=", &mut version);
            });
        }

        Ok((id, version))
    }

    /// Return the OS id (e.g. "fedora"), if found.
    pub(crate) fn os_id(&self) -> Option<&String> {
        self.os_id.as_ref()
    }

    /// Return the OS version (e.g. "38"), if found.
    pub(crate) fn os_version(&self) -> Option<&String> {
        self.os_version.as_ref()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn inspector_init() {
        assert!(super::inspector().is_ok());
    }

    #[test]
    fn os_info() {
        let inspector = super::inspector().unwrap();

        assert_eq!(inspector.os_id(), Some(&"fedora".to_string()));
        assert_eq!(inspector.os_version(), Some(&"39".to_string()));
    }
}
