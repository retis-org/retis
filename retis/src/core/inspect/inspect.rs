use std::path::PathBuf;

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
}

impl Inspector {
    fn from(kconf: Option<&PathBuf>) -> Result<Inspector> {
        Ok(Inspector {
            kernel: KernelInspector::from(kconf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn inspector_init() {
        assert!(super::inspector().is_ok());
    }
}
