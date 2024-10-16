//! Handles the file (json) to Rust event retrieval and the unmarshaling process.

use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use anyhow::{anyhow, Result};

use super::Event;

/// File events factory retrieving and unmarshaling events
/// parts.
pub struct FileEventsFactory {
    reader: BufReader<File>,
}

impl FileEventsFactory {
    pub fn new<P>(file: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        Ok(FileEventsFactory {
            reader: BufReader::new(
                File::open(&file)
                    .map_err(|e| anyhow!("Could not open {}: {e}", file.as_ref().display()))?,
            ),
        })
    }
}

impl FileEventsFactory {
    /// Retrieve the next event or None if we've reached the end of the file.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        let mut line = String::new();

        match self.reader.read_line(&mut line) {
            Err(e) => return Err(e.into()),
            Ok(0) => return Ok(None),
            Ok(_) => (),
        }

        Ok(Some(Event::from_json(line)?))
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
