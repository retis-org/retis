use anyhow::Result;
use once_cell::sync::OnceCell;

use super::kernel::KernelInspector;

static INSPECTOR: OnceCell<Inspector> = OnceCell::new();

/// Gets a reference on the inspector.
pub(crate) fn inspector() -> Result<&'static Inspector> {
    INSPECTOR.get_or_try_init(Inspector::new)
}

/// Provides helpers to inspect various information about the system and the
/// kernel. Used as a singleton.
pub(crate) struct Inspector {
    /// Kernel part of the inspector.
    pub(crate) kernel: KernelInspector,
}

impl Inspector {
    fn new() -> Result<Inspector> {
        Ok(Inspector {
            kernel: KernelInspector::new()?,
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
