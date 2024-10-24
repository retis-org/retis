//! Handles the file (json) to Rust event retrieval and the unmarshaling process.

use std::{
    fs::File,
    io::{BufRead, BufReader, Seek},
    path::Path,
};

use anyhow::{anyhow, bail, Result};

use super::{Event, EventSeries};

// Type of file that is being processed.
#[derive(Debug, Clone)]
pub enum FileType {
    /// File contains events.
    Event,
    /// File contains event series.
    Series,
}

/// File events factory retrieving and unmarshaling events
/// parts.
pub struct FileEventsFactory {
    reader: BufReader<File>,
    filetype: FileType,
}

impl FileEventsFactory {
    pub fn new<P>(file: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let mut reader = BufReader::new(
            File::open(&file)
                .map_err(|e| anyhow!("Could not open {}: {e}", file.as_ref().display()))?,
        );
        let filetype = Self::detect_type(&mut reader)?;

        Ok(FileEventsFactory { reader, filetype })
    }
}

impl FileEventsFactory {
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
            Ok(_) => Ok(Some(Event::from_json(line)?)),
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
            Ok(_) => Ok(Some(EventSeries::from_json(line)?)),
        }
    }

    fn detect_type<T>(reader: &mut T) -> Result<FileType>
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

        match first {
            serde_json::Value::Object(_) => Ok(FileType::Event),
            serde_json::Value::Array(_) => Ok(FileType::Series),
            _ => bail!("File contains invalid json data"),
        }
    }

    pub fn file_type(&self) -> &FileType {
        &self.filetype
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_from_file() {
        let mut fact = FileEventsFactory::new("test_data/test_events.json").unwrap();

        let mut events = Vec::new();
        while let Some(event) = fact.next_event().unwrap() {
            println!("event: {:#?}", event.to_json());
            events.push(event)
        }
        assert!(events.len() == 4);
    }
}
