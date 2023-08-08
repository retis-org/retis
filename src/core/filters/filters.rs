/// eBPF filter wrapper containing the sequence of bytes composing the eBPF program
use std::{collections::HashMap, sync::Mutex};

use anyhow::{bail, Result};
use once_cell::sync::Lazy;

#[derive(Clone)]
pub(crate) struct BpfFilter(pub(crate) Vec<u8>);

#[derive(Clone)]
pub(crate) enum Filter {
    Packet(BpfFilter),
}

static FM: Lazy<Mutex<HashMap<u32, Filter>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub(crate) fn register_filter(r#type: u32, filter: &Filter) -> Result<()> {
    if FM.lock().unwrap().insert(r#type, filter.clone()).is_some() {
        bail!("Filter (k: {}) already registered", r#type);
    }
    Ok(())
}

pub(crate) fn get_filter(r#type: u32) -> Option<Filter> {
    FM.lock().unwrap().get(&r#type).cloned()
}
