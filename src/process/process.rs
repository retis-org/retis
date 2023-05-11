#![allow(dead_code)] // FIXME
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use log::debug;

use crate::{
    core::{
        events::{Event, EventFactory, SectionFactories},
        signals::Running,
    },
    output::Output,
};

/// Trait to process events
pub(crate) trait ProcessorAction {
    /// Process an event and generate an Vector of events.
    fn process_one(&mut self, e: Event) -> Result<Vec<Event>>;
    /// Stop processing. Remaining events can be returned.
    fn stop(&mut self) -> Result<Vec<Event>>;
}

/// ProcessStage is a wrapper around a ProcessorAction that handles input & output of events via
/// mpsc channels.
struct ProcessorStage {
    name: String,
    action: Box<dyn ProcessorAction>,
    next: Option<Box<ProcessorStage>>,
}

impl ProcessorStage {
    /// Create a new named Stage with a ProcessorAction
    fn new(name: String, action: Box<dyn ProcessorAction>) -> Result<Self> {
        Ok(Self {
            name,
            action,
            next: None,
        })
    }

    /// Chain a processor with the next one
    fn chain(&mut self, next: Box<ProcessorStage>) -> Result<()> {
        if self.next.is_some() {
            bail!("{}: stage already chained", self.name);
        } else {
            self.next = Some(next);
        }
        Ok(())
    }

    /// Stop the processor. Join the thread.
    fn stop(&mut self, mut remaining: Vec<Event>) -> Result<()> {
        debug!("{}: stop", self.name);
        // Send the last remaining events to the action.
        let mut result = Vec::new();
        for event in remaining.drain(..) {
            result.append(&mut self.action.process_one(event)?);
        }
        // Tell the action to stop. This can also generate some remaining events.
        result.append(&mut self.action.stop()?);

        // Send all the remaining events down the chain.
        if let Some(mut next) = self.next.take() {
            next.stop(result)?;
        }
        Ok(())
    }

    fn process_one(&mut self, event: Event) -> Result<()> {
        debug!("{}: processing event", self.name);
        let mut result = self.action.process_one(event)?;

        // If the action generates events, pass them down the chain.
        if let Some(next) = &mut self.next {
            for event in result.drain(..) {
                next.process_one(event)?;
            }
        }
        Ok(())
    }
}

/// A ProcessorStage made of a set of Outputs
#[derive(Default)]
pub(crate) struct OutputAction {
    outputs: Vec<Box<dyn Output + 'static>>,
}

impl OutputAction {
    /// Create an output stage from a vector of Outputs. Note the vector is consumed and object's
    /// ownership is moved.
    pub(crate) fn from(out: &mut Vec<Box<dyn Output + 'static>>) -> Self {
        let mut outputs = Vec::<Box<dyn Output>>::default();
        outputs.append(out);

        Self { outputs }
    }
}

impl ProcessorAction for OutputAction {
    fn process_one(&mut self, e: Event) -> Result<Vec<Event>> {
        for o in self.outputs.iter_mut() {
            o.output_one(&e)?;
        }
        Ok(Vec::new())
    }
    fn stop(&mut self) -> Result<Vec<Event>> {
        for o in self.outputs.iter_mut() {
            o.flush()?;
        }
        Ok(Vec::new())
    }
}

/// Processor is in charge of coordinating the event generation and processing.
/// Any number of ProcessorActions can be added. Note OutputActions can be built from Output
/// objects to be conveniently added as stages.
/// Finally, when run, it will start a loop in which generated events will be processed by each
/// processor (in order of insertion) and finally they will be outputted by the provided Output
/// objects.
pub(crate) struct Processor<'a, F>
where
    F: EventFactory,
{
    source: &'a mut F,
    head: Option<Box<ProcessorStage>>,
    output: Vec<Box<dyn Output>>,
    duration: Duration,
}

impl<'a, F> Processor<'a, F>
where
    F: EventFactory,
{
    /// Create a new PostProcessor on a file.
    pub(crate) fn new(source: &'a mut F) -> Result<Self> {
        Ok(Processor {
            source,
            head: None,
            output: Vec::new(),
            duration: Duration::from_secs(1),
        })
    }

    /// Add a processor stage.
    pub(crate) fn add_stage(
        &mut self,
        name: String,
        action: Box<dyn ProcessorAction>,
    ) -> Result<()> {
        let stage = Box::new(ProcessorStage::new(name, action)?);

        if let Some(last) = self.last_mut() {
            last.chain(stage)?;
        } else {
            self.head = Some(stage);
        }
        Ok(())
    }

    pub(crate) fn set_duration(&mut self, duration: Duration) -> Result<()> {
        self.duration = duration;
        Ok(())
    }

    /// Start processing
    pub(crate) fn run(&'a mut self, state: Running, factories: SectionFactories) -> Result<()> {
        // Start the factory
        self.source.start(factories)?;

        // Main loop:
        let head = self
            .head
            .as_mut()
            .ok_or_else(|| anyhow!("No stages have been added"))?;
        while state.running() {
            match self.source.next_event(Some(self.duration))? {
                Some(event) => {
                    head.process_one(event)?;
                }
                None => continue,
            }
        }
        head.stop(Vec::new())?;
        Ok(())
    }

    /// Get a mutable reference to the last stage in the pipeline.
    fn last_mut(&mut self) -> Option<&mut Box<ProcessorStage>> {
        match self.head {
            Some(ref mut next) => {
                let mut iterator = next;
                loop {
                    let it = iterator;
                    match it.next {
                        Some(ref mut next) => {
                            iterator = next;
                        }
                        None => return Some(it),
                    }
                }
            }
            None => None,
        }
    }
}
