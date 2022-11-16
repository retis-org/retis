//! # Dynamic
//!
//! Wrapper around clap's Command that allows for dynamic registration of modules.
//! Each registered module will have its own section in the final long help.

/// DynamicCommand is a wrapper around clap's Command that supports modules all around the code
/// base to dynamically register arguments using clap's derive interface.
#[derive(Debug)]
pub(crate) struct DynamicCommand {
}

impl DynamicCommand {
}

