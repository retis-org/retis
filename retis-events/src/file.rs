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
    filetype: Option<FileType>,
}

impl FileEventsFactory {
    pub fn new<P>(file: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let mut fact = FileEventsFactory {
            reader: BufReader::new(
                File::open(&file)
                    .map_err(|e| anyhow!("Could not open {}: {e}", file.as_ref().display()))?,
            ),
            filetype: None,
        };
        fact.detect_type()?;
        Ok(fact)
    }
}

impl FileEventsFactory {
    /// Retrieve the next event or None if we've reached the end of the file.
    /// It returns an error if the file contains sorted EventSeries.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        match self
            .filetype
            .as_ref()
            .ok_or_else(|| anyhow!("File type not determined"))?
        {
            FileType::Event => (),
            FileType::Series => bail!("Incorrect filetype. Use next_series()."),
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
        match self
            .filetype
            .as_ref()
            .ok_or_else(|| anyhow!("File type not determined"))?
        {
            FileType::Event => bail!("Incorrect filetype. Use next_event()."),
            FileType::Series => (),
        }
        let mut line = String::new();

        match self.reader.read_line(&mut line) {
            Err(e) => Err(e.into()),
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(EventSeries::from_json(line)?)),
        }
    }

    fn detect_type(&mut self) -> Result<()> {
        let mut line = String::new();

        match self.reader.read_line(&mut line) {
            Err(e) => return Err(e.into()),
            Ok(0) => return Ok(()), // The file is empty, let the next_* function return None
            Ok(_) => (),
        }
        self.reader.rewind()?;

        let first: serde_json::Value = serde_json::from_str(line.as_str())
            .map_err(|e| anyhow!("Failed to parse event file: {:?}", e))?;

        match first {
            serde_json::Value::Object(_) => self.filetype = Some(FileType::Event),
            serde_json::Value::Array(_) => self.filetype = Some(FileType::Series),
            _ => bail!("File contains invalid json data"),
        }
        Ok(())
    }

    pub fn file_type(&self) -> Result<&FileType> {
        self.filetype
            .as_ref()
            .ok_or_else(|| anyhow!("Unknown file type"))
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
