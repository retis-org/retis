//! # Common
//!
//! Module providing infrastructure shared by all probes
use anyhow::{bail, Result};

use once_cell::sync::OnceCell;

static EBPF_DEBUG: OnceCell<bool> = OnceCell::new();

/// Sets global ebpf debug flag.
///
/// It must only be set once.
/// It will return Ok if it's the first time the it's been set or Err if it was already set.
pub(crate) fn set_ebpf_debug(debug: bool) -> Result<()> {
    EBPF_DEBUG
        .set(debug)
        .or_else(|_| bail!("ebpf_debug was already set"))?;
    Ok(())
}

/// Returns the current value of the global ebpf debug flag.
///
/// If called before [`set_ebpf_debug`] has been called, it will be set to false.
pub(crate) fn get_ebpf_debug() -> bool {
    // Always debug when running tests.
    if cfg!(test) {
        true
    } else {
        *EBPF_DEBUG.get_or_init(|| false)
    }
}
