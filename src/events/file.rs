//! Handles the file (json) to Rust event retrieval and the unmarshaling process.

use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    time::Duration,
};

use anyhow::{anyhow, Result};
use log::debug;

use super::{Event, EventFactory, EventResult, SectionFactories};
use crate::module::ModuleId;

/// File events factory retrieving and unmarshaling events
/// parts.
pub(crate) struct FileEventsFactory {
    reader: BufReader<File>,
    factories: SectionFactories,
}

impl FileEventsFactory {
    pub(crate) fn new<P>(file: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        Ok(FileEventsFactory {
            reader: BufReader::new(
                File::open(&file)
                    .map_err(|e| anyhow!("Could not open {}: {e}", file.as_ref().display()))?,
            ),
            factories: HashMap::new(),
        })
    }
}

impl EventFactory for FileEventsFactory {
    fn start(&mut self, section_factories: SectionFactories) -> Result<()> {
        self.factories = section_factories;
        Ok(())
    }

    /// Stops the factory events collection.
    fn stop(&mut self) -> Result<()> {
        Ok(())
    }

    /// Retrieve the next event. This is a blocking call and never returns EOF.
    fn next_event(&mut self, _timeout: Option<Duration>) -> Result<EventResult> {
        let mut event = Event::new();
        let mut line = String::new();

        match self.reader.read_line(&mut line) {
            Err(e) => return Err(e.into()),
            Ok(0) => return Ok(EventResult::Eof),
            Ok(_) => (),
        }

        let mut event_js: HashMap<String, serde_json::Value> = serde_json::from_str(line.as_str())
            .map_err(|e| anyhow!("Failed to parse json event at line {line}: {e}"))?;

        for (owner, section) in event_js.drain() {
            let owner = ModuleId::from_str(owner.as_str())?;
            let factory = self
                .factories
                .get(&owner)
                .ok_or_else(|| anyhow!("Missing SectionFactory for section owner {owner}"))?;

            debug!("Unmarshaling event section {owner}: {section}");
            event.insert_section(
                owner,
                factory.from_json(section).map_err(|e| {
                    anyhow!("Failed to create EventSection for owner {owner} from json: {e}")
                })?,
            )?;
        }
        Ok(EventResult::Event(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::get_modules;
    #[test]
    fn read_from_file() {
        let modules = get_modules().unwrap();
        let mut fact = FileEventsFactory::new("test_data/test_events.json").unwrap();
        let factories = modules.section_factories().unwrap();
        fact.start(factories).unwrap();

        let mut events = Vec::new();
        while let EventResult::Event(event) = fact.next_event(None).unwrap() {
            println!("event: {:#?}", event.to_json());
            events.push(event)
        }
        assert!(events.len() == 4);
    }
}
