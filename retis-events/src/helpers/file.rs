//! Handles the file (json) to Rust event retrieval and the unmarshaling process.

use std::{
    fs::File,
    io::{BufRead, BufReader, Read, Seek},
    path::Path,
};

use anyhow::{anyhow, bail, Result};

use crate::{
    compat::{json, CompatVersion},
    Event, EventSeries,
};

// Type of file that is being processed.
#[derive(Debug, Clone)]
pub enum FileType {
    /// File contains events.
    Event,
    /// File contains event series.
    Series,
}

pub trait ReadSeek: Read + Seek + Send + Sync {}
impl<T> ReadSeek for T where T: Read + Seek + Send + Sync {}

/// File events factory retrieving and unmarshaling events
/// parts.
pub struct FileEventsFactory {
    reader: BufReader<Box<dyn ReadSeek>>,
    filetype: FileType,
    compat_version: CompatVersion,
}

impl FileEventsFactory {
    pub fn from_path<P>(file: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        Self::new(Box::new(File::open(&file).map_err(|e| {
            anyhow!("Could not open {}: {e}", file.as_ref().display())
        })?))
    }

    pub fn new(reader: Box<dyn ReadSeek>) -> Result<Self> {
        let mut reader = BufReader::new(reader);
        let (filetype, compat_version) = Self::detect_type(&mut reader)?;

        Ok(FileEventsFactory {
            reader,
            filetype,
            compat_version,
        })
    }

    /// Returns true if the events are not from the latest (event format)
    /// version.
    pub fn is_compat(&self) -> bool {
        self.compat_version != CompatVersion::LATEST
    }

    /// Retrieve the next event or None if we've reached the end of the file.
    /// It returns an error if the file contains sorted EventSeries.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        match self.filetype {
            FileType::Event => (),
            FileType::Series => bail!("Cannot read event from sorted file"),
        }
        let mut line = String::new();

        match self.reader.read_line(&mut line) {
            Err(e) => Err(e.into()),
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(json::from_str(line.as_str(), self.compat_version)?)),
        }
    }

    /// Retrieve the next series or None if we've reached the end of the file.
    /// It returns an error if the file contains unsorted Events.
    pub fn next_series(&mut self) -> Result<Option<EventSeries>> {
        match self.filetype {
            FileType::Event => bail!("Cannot read series from unsorted file"),
            FileType::Series => (),
        }
        let mut line = String::new();

        match self.reader.read_line(&mut line) {
            Err(e) => Err(e.into()),
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(json::from_str(line.as_str(), self.compat_version)?)),
        }
    }

    fn detect_type<T>(reader: &mut T) -> Result<(FileType, CompatVersion)>
    where
        T: BufRead + Seek,
    {
        let mut line = String::new();

        match reader.read_line(&mut line) {
            Err(e) => return Err(e.into()),
            Ok(0) => return Err(anyhow!("File is empty")),
            Ok(_) => (),
        }
        reader.rewind()?;

        let first: serde_json::Value = serde_json::from_str(line.as_str())
            .map_err(|e| anyhow!("Failed to parse event file: {:?}", e))?;

        Ok(match first {
            serde_json::Value::Object(ref obj) => (FileType::Event, guess_version(obj)?),
            serde_json::Value::Array(mut vec) => match vec.pop() {
                Some(serde_json::Value::Object(ref map)) => (FileType::Series, guess_version(map)?),
                _ => bail!("Invalid or missing events"),
            },
            _ => bail!("File contains invalid json data"),
        })
    }

    pub fn file_type(&self) -> &FileType {
        &self.filetype
    }
}

/// Guess an event compatibility version given a first partially marshalled
/// event.
pub(crate) fn guess_version(
    val: &serde_json::Map<String, serde_json::Value>,
) -> Result<CompatVersion> {
    if let Some(serde_json::Value::Object(startup)) = val.get("startup") {
        if let Some(serde_json::Value::String(version)) = startup.get("retis_version") {
            return CompatVersion::from_retis_version(version);
        }
    }
    Err(anyhow!("Cannot find version in startup event"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_from_file() {
        let mut fact = FileEventsFactory::from_path("test_data/test_events.json").unwrap();

        let mut events = Vec::new();
        while let Some(event) = fact.next_event().unwrap() {
            println!("event: {:#?}", serde_json::json!(event));
            events.push(event)
        }
        assert!(events.len() == 5);
    }
}
