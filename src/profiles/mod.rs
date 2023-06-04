//! # Profiles
//!
//! Profiles are yaml files that define well-known arguments that shall be used to make retis
//! target certain use cases.
//!

// Re-export collector.rs
#[allow(clippy::module_inception)]
pub(crate) mod profiles;
#[allow(unused_imports)]
pub(crate) use profiles::*;

pub(crate) mod cli;
pub(crate) mod version;
