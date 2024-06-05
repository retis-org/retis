//! # Inspection helpers
//!
//! Provides support for inspecting the system, kernel, symbols, etc.

// Re-export inspect.rs
#[allow(clippy::module_inception)]
pub(crate) mod inspect;
pub(crate) use inspect::*;

/* Benchmarks are run from the top directory where as tests are run from within
 * the retis workspace. */
pub(crate) static BASE_TEST_DIR: &str = match (cfg!(test), cfg!(feature = "benchmark")) {
    (false, true) => "retis",
    (_, _) => ".",
};

mod btf;
pub(crate) mod check;
mod kernel;
pub(crate) mod kernel_version;
