/// # Writer handling file rotation
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    ops::Drop,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, Result};
use log::error;
use regex::Regex;

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
    head: Option<Vec<u8>>,
    target_index: usize,
    written: usize,
}

impl RotateWriter {
    /// Create a new RotateWriter given a file path, a rotation strategy and
    /// head raw data to be stored at the start of each file.
    pub(crate) fn new(file: &Path, rotation: Rotation, head: Option<Vec<u8>>) -> Result<Self> {
        let (inner, written) = Self::new_file(file, head.as_deref())?;

        Ok(Self {
            inner,
            rotation,
            target: file.to_path_buf(),
            head,
            target_index: 0,
            written,
        })
    }

    fn new_file(target: &Path, head: Option<&[u8]>) -> io::Result<(BufWriter<File>, usize)> {
        let mut w = BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(target)?,
        );

        let mut written = 0;
        if let Some(head) = head {
            written += w.write(head)?;
            written += w.write(b"\n")?;
        }

        Ok((w, written))
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
        (self.inner, self.written) = Self::new_file(&self.target, self.head.as_deref())?;

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
