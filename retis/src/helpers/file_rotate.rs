/// # Writer handling file rotation
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    ops::Drop,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use log::error;
use regex::Regex;

use crate::{
    core::events::RetisEventsFactory, events::StartupEvent, helpers::time::monotonic_clock_offset,
};

#[derive(Eq, PartialEq)]
pub(crate) enum Rotation {
    None,
    Size(usize),
}

impl Rotation {
    /// Convert an str representation of a limit to a `Rotation`.
    ///
    /// Accepted values are numbers suffixed with a unit size (MB or GB).
    pub(crate) fn from_str(limit: &str) -> Result<Self> {
        let re = Regex::new(r"(\d+)(M|G)B")?;
        let matches = re
            .captures(limit)
            .ok_or_else(|| anyhow!("Invalid limit format ({limit})"))?;

        // Unwrap as the regex already checked the second group was mandatory.
        let factor = match matches.get(2).unwrap().as_str() {
            "M" => 1000 * 1000,
            "G" => 1000 * 1000 * 1000,
            _ => 1,
        };

        // Unwrap as the regex already checked the first group was mandatory.
        let limit = usize::from_str(matches.get(1).unwrap().as_str())? * factor;

        Ok(Rotation::Size(limit))
    }
}

pub(crate) struct RotateWriter {
    inner: BufWriter<File>,
    rotation: Rotation,
    target: PathBuf,
    target_index: usize,
    written: usize,
    events_factory: Arc<RetisEventsFactory>,
}

impl RotateWriter {
    pub(crate) fn new(
        file: &Path,
        rotation: Rotation,
        events_factory: Arc<RetisEventsFactory>,
    ) -> Result<Self> {
        Ok(Self {
            inner: Self::new_file(file, &events_factory)?,
            rotation,
            target: file.to_path_buf(),
            target_index: 0,
            written: 0,
            events_factory,
        })
    }

    fn new_file(target: &Path, events_factory: &RetisEventsFactory) -> io::Result<BufWriter<File>> {
        let w = BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(target)?,
        );

        // Issue a Startup event. This is used at post-processing time to have
        // insights about the collection environment.
        events_factory
            .add_event(|event| {
                event.startup = Some(StartupEvent {
                    retis_version: option_env!("RELEASE_VERSION")
                        .unwrap_or("unspec")
                        .to_string(),
                    clock_monotonic_offset: monotonic_clock_offset()?,
                });
                Ok(())
            })
            .map_err(|e| io::Error::other(format!("Cannot insert startup event: {e}")))?;

        Ok(w)
    }

    fn close(&mut self) -> io::Result<()> {
        // Flush the current buffer.
        self.flush()?;

        // Move the file, if needed.
        match self.rotation {
            Rotation::None => (),
            Rotation::Size(_) => {
                let mut target = self.target.clone().into_os_string();
                target.push(format!("{}", self.target_index));
                self.target_index += 1;

                fs::rename(&self.target, &target)?;
            }
        }

        Ok(())
    }

    /// Rotate the file.
    fn rotate(&mut self) -> io::Result<()> {
        if self.rotation == Rotation::None {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Cannot rotate output without a rotation policy",
            ));
        }

        // Close and rename the target file.
        self.close()?;

        // Create the new file.
        self.inner = Self::new_file(&self.target, &self.events_factory)?;

        Ok(())
    }
}

impl Write for RotateWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.rotation {
            Rotation::None => (),
            Rotation::Size(limit) => {
                if self.written + buf.len() > limit {
                    self.rotate()?;
                    self.written = 0;
                }
            }
        }

        let written = self.inner.write(buf)?;
        self.written += written;

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Drop for RotateWriter {
    fn drop(&mut self) {
        if let Err(e) = self.close() {
            error!("Could not close {}: {e}", self.target.display());
        }
    }
}
