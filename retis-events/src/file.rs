//! Handles the file (json) to Rust event retrieval and the unmarshaling process.

use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    time::Duration,
};

use anyhow::{anyhow, Result};

use super::{Event, EventResult};

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
    /// Retrieve the next event. This is a blocking call and never returns EOF.
    pub fn next_event(&mut self, _timeout: Option<Duration>) -> Result<EventResult> {
        let mut line = String::new();

        match self.reader.read_line(&mut line) {
            Err(e) => return Err(e.into()),
            Ok(0) => return Ok(EventResult::Eof),
            Ok(_) => (),
        }

        Ok(EventResult::Event(Event::from_json(line)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_from_file() {
        let mut fact = FileEventsFactory::new("test_data/test_events.json").unwrap();

        let mut events = Vec::new();
        while let EventResult::Event(event) = fact.next_event(None).unwrap() {
            println!("event: {:#?}", event.to_json());
            events.push(event)
        }
        assert!(events.len() == 4);
    }
}
