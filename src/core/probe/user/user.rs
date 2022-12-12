#![allow(dead_code)] // FIXME

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Result};

/// Integer to represent all pids.
const PID_ALL: i32 = -1;

/// Specific types of errors that Process can generate.
#[derive(thiserror::Error, Debug, PartialEq)]
pub(crate) enum ProcessError {
    /// Emitted when the process was not found.
    #[error("Process not found")]
    NotFound,
    /// Emitted when there were too many processes matching input parameters.
    #[error("Too many processes found")]
    TooMany,
}

/// Object that represets one running processes to which probes can be attached.
#[derive(Debug)]
pub(crate) struct Process {
    /// Process ID.
    pid: i32,
    /// The path of the program.
    path: PathBuf,
}

impl Process {
    /// Create a new Process object with a specific pid
    pub(crate) fn new(pid: i32) -> Result<Process> {
        let proc_dir = PathBuf::from("/proc").join(pid.to_string());
        if !proc_dir.exists() {
            bail!(ProcessError::NotFound);
        }

        let path = match proc_dir.join("exe").read_link() {
            Ok(bin_path) => bin_path
                .to_str()
                .ok_or_else(|| anyhow!("Failed to process path"))?
                .into(),
            Err(e) => {
                bail!("Cannot open executable path for process {}: {}", pid, e)
            }
        };

        Ok(Process { pid, path })
    }

    /// Create a new Process object with a specific cmd.
    pub(crate) fn from_cmd(cmd: &str) -> Result<Process> {
        let mut pid: i32 = PID_ALL;
        // Look in /proc for a process with this cmd.
        for entry in Path::new("/proc/").read_dir()? {
            let entry = entry?;
            if !entry.path().is_dir()
                || !entry.path().join("comm").exists()
                || fs::read_to_string(entry.path().join("comm"))?
                    .trim()
                    .ne(cmd)
            {
                continue;
            }

            // Return a specific error indicating there are more than once process with this
            // cmd so that the user can decide which one to probe.
            if pid != PID_ALL {
                bail!(ProcessError::TooMany);
            }
            pid = match entry
                .file_name()
                .into_string()
                .map_err(|s| anyhow!("Unable to convert path into string {:?}", s))?
                .parse::<i32>()
            {
                Ok(pid) => pid,
                Err(_) => {
                    continue;
                }
            };
        }
        if pid != PID_ALL {
            Process::new(pid)
        } else {
            bail!(ProcessError::NotFound);
        }
    }

    /// Create a new Process object that represent all existing and future processes with a
    /// specific path.
    pub(crate) fn all(path: &str) -> Result<Process> {
        let path = PathBuf::from(path);
        if !path.exists() {
            bail!(ProcessError::NotFound);
        }
        Ok(Process { pid: PID_ALL, path })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_create() -> Result<()> {
        assert!(Process::new(std::process::id() as i32).is_ok());
        // UINT32_MAX is way higher than typical PID_MAX.
        let p = Process::new(-1);
        assert!(
            p.is_err()
                && p.unwrap_err().downcast_ref::<ProcessError>() == Some(&ProcessError::NotFound)
        );
        Ok(())
    }

    #[test]
    fn process_from_cmd() -> Result<()> {
        let p = Process::from_cmd("cargo");
        // The test should have been run by cargo so there's at least one process running with that
        // cmd.
        assert!(
            (p.is_err()
                && p.as_ref().unwrap_err().downcast_ref::<ProcessError>()
                    == Some(&ProcessError::TooMany))
                || p.is_ok()
        );

        let p = Process::from_cmd("_no_way_a_process_with_this_cmd_exists__");
        assert!(
            p.is_err()
                && p.unwrap_err().downcast_ref::<ProcessError>() == Some(&ProcessError::NotFound)
        );
        Ok(())
    }

    #[test]
    fn process_all() -> Result<()> {
        let p = Process::all("_no_way_this_path/_exists");
        assert!(
            p.is_err()
                && p.unwrap_err().downcast_ref::<ProcessError>() == Some(&ProcessError::NotFound)
        );

        let p = Process::all("/bin/sh");
        assert!(p.is_ok() && p.unwrap().pid == PID_ALL);
        Ok(())
    }
}
