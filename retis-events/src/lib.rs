//! # Retis events
//!
//! This crate contains the definitions of the types that conform the retis event as
//! well as some ancillary structs and helpers to facilitate parsing, displaying and
//! inspecting events.

pub mod events;
pub use events::*;

pub mod display;
pub use display::*;

pub(crate) mod compat;

pub mod file;
pub mod helpers;
#[cfg(feature = "python")]
pub mod python;
#[cfg(feature = "python-embed")]
pub mod python_embed;

pub mod common;
pub use common::*;
pub mod ct;
pub use ct::*;
pub mod dev;
pub use dev::*;
pub mod kernel;
pub use kernel::*;
pub mod nft;
pub use nft::*;
pub mod ns;
pub use ns::*;
pub mod ovs;
pub use ovs::*;
pub mod packet;
pub use packet::*;
pub mod time;
pub use time::*;
pub mod skb;
pub use skb::*;
pub mod skb_drop;
pub use skb_drop::*;
pub mod skb_tracking;
pub use skb_tracking::*;
pub mod user;
pub use user::*;

// Re-export derive macros.
use retis_derive::*;

#[cfg(feature = "python-lib")]
use pyo3::prelude::*;

#[cfg(feature = "python-lib")]
#[pymodule]
fn retis(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<python::PyEvent>()?;
    m.add_class::<python::PyEventSeries>()?;
    m.add_class::<python::PyEventReader>()?;
    m.add_class::<python::PySeriesReader>()?;
    m.add_class::<python::PyEventFile>()?;
    Ok(())
}
