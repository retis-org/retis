#![allow(dead_code)] // FIXME

use std::{any::Any, collections::HashMap, fmt, path::PathBuf};

use anyhow::{anyhow, bail, Result};

use crate::EventSectionFactory;
use crate::{
    core::{
        probe::common::{Counters, CountersKey},
        user::proc::Process,
    },
    events::{bpf::BpfRawSection, *},
};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct UsdtProbe {
    /// The provider name.
    pub provider: String,
    /// The probe's name.
    pub name: String,
    /// The probe's symbol.
    pub ksym: u64,

    /// The target's path
    pub path: PathBuf,
    /// The target's pid
    pub pid: i32,
}

impl UsdtProbe {
    /// Return a new UsdtProbe.
    pub(crate) fn new(proc: &Process, target: &str) -> Result<Self> {
        let (path, note) = proc
            .get_note(target)?
            .ok_or_else(|| anyhow!("Target not found"))?;

        Ok(UsdtProbe {
            provider: note.provider.to_owned(),
            name: note.name.to_owned(),
            ksym: note.addr,
            path: path.to_owned(),
            pid: proc.pid(),
        })
    }

    /// Creates a dummy UsdtProbe. Using it like a valid one is buggy.
    pub(crate) fn dummy() -> Self {
        Self {
            provider: "".to_string(),
            name: "".to_string(),
            ksym: 0,
            path: PathBuf::new(),
            pid: -1,
        }
    }

    /// Return a printable name.
    pub(crate) fn name(&self) -> String {
        format!("usdt:{}:{}", self.provider, self.name)
    }

    /// Generate the probe BPF configuration from a list of options.
    pub(crate) fn gen_counters(&self) -> Result<(CountersKey, Counters)> {
        Ok((
            CountersKey {
                sym_addr: self.ksym,
                pid: self.pid as u64,
            },
            Counters::default(),
        ))
    }
}

impl fmt::Display for UsdtProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.path.display(), self.provider, self.name)
    }
}

#[derive(Default, EventSectionFactory)]
pub(crate) struct UserEventFactory {
    cache: HashMap<String, Box<dyn Any>>,
}

impl RawEventSectionFactory for UserEventFactory {
    fn from_raw(&mut self, mut raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        if raw_sections.len() != 1 {
            bail!("User event from BPF must be a single section")
        }

        // Unwrap as we just checked the vector contains 1 element.
        let raw = raw_sections.pop().unwrap();

        if raw.data.len() != 17 {
            bail!(
                "Section data is not the expected size {} != 17",
                raw.data.len()
            );
        }

        let symbol = u64::from_ne_bytes(raw.data[0..8].try_into()?);
        let pid_tid = u64::from_ne_bytes(raw.data[8..16].try_into()?);
        let r#type = u8::from_ne_bytes(raw.data[16..17].try_into()?);

        // Split pid and tid
        let pid = (pid_tid >> 32) as i32;
        let tid = (pid_tid & 0xFFFFFFFF) as i32;

        let pid_key = format!("user_proc_{pid}");
        // Try to obtain the Process object from the Context.
        let proc = match self.cache.get(&pid_key) {
            Some(val) => val.downcast_ref::<Process>(),
            None => {
                // Not found, create it, insert it and retrieve it.
                let proc = Box::new(Process::from_pid(pid)?);
                self.cache.insert(pid_key.clone(), proc);
                self.cache
                    .get(&pid_key)
                    .ok_or_else(|| anyhow!("Failed to insert process"))?
                    .downcast_ref::<Process>()
            }
        }
        .ok_or_else(|| anyhow!("Failed to retrieve process information"))?;

        let note = proc
            .get_note_from_symbol(symbol)?
            .ok_or_else(|| anyhow!("Failed to get symbol information"))?;

        Ok(Box::new(UserEvent {
            pid,
            tid,
            symbol: format!("{note}"),
            ip: symbol,
            path: proc
                .path()
                .to_str()
                .ok_or_else(|| anyhow!("Wrong binary path"))?
                .to_string(),
            probe_type: match r#type {
                1 => "usdt",
                _ => "unknown",
            }
            .to_string(),
        }))
    }
}
