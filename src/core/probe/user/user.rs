#![allow(dead_code)] // FIXME

use std::{fmt, path::PathBuf};

use anyhow::{anyhow, Result};

use crate::core::probe::user::proc::Process;

#[derive(Debug, PartialEq)]
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
        let note = proc
            .usdt_info()
            .ok_or_else(|| anyhow!("No USDT information available"))?
            .get_note(target)?
            .ok_or_else(|| anyhow!("Target not found"))?;

        Ok(UsdtProbe {
            provider: note.provider.to_owned(),
            name: note.name.to_owned(),
            ksym: note.addr,
            path: proc.path().to_owned(),
            pid: proc.pid(),
        })
    }

    /// Return a printable name.
    pub(crate) fn name(&self) -> String {
        format!("usdt:{}:{}", self.provider, self.name)
    }
}

impl fmt::Display for UsdtProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.path.display(), self.provider, self.name)
    }
}
