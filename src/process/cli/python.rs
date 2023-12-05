use std::{fs, path::PathBuf, time::Duration};

use anyhow::Result;
use clap::{arg, Parser};
use pyo3::{exceptions::PySyntaxError, prelude::*, types::PyDict};
use rustyline::{error::ReadlineError, DefaultEditor};

use crate::{
    cli::*,
    core::events::{
        file::FileEventsFactory,
        python::{PyEvent, PyEventList},
        Event, EventFactory, EventResult,
    },
    module::Modules,
};

/// Launches a Python interactive cli with events imported.
#[derive(Parser, Debug, Default)]
#[command(name = "python")]
pub(crate) struct PythonCli {
    #[arg(default_value = "retis.data", help = "File from which to read events")]
    pub(super) input: PathBuf,
    #[arg(long, help = "Python script to execute")]
    pub(super) exec: Option<PathBuf>,
}

impl SubCommandParserRunner for PythonCli {
    fn run(&mut self, modules: Modules) -> Result<()> {
        // Create event factory.
        let mut factory = FileEventsFactory::new(self.input.as_path())?;
        factory.start(modules.section_factories()?)?;

        let mut events = Vec::new();
        use EventResult::*;
        loop {
            match factory.next_event(Some(Duration::from_secs(1)))? {
                Event(event) => events.push(event),
                Eof => break,
                Timeout => continue,
            }
        }

        Python::with_gil(|py| -> PyResult<()> {
            let shell = PyShell::new(py, events)?;
            match &self.exec {
                Some(script) => shell.run(&fs::read_to_string(script)?),
                None => shell.interactive(),
            }
        })?;

        Ok(())
    }
}

struct PyShell<'a> {
    py: Python<'a>,
    globals: Bound<'a, PyDict>,
}

impl<'a> PyShell<'a> {
    fn new(py: Python<'a>, mut events: Vec<Event>) -> PyResult<Self> {
        let globals = PyDict::new_bound(py);
        globals.set_item(
            "events",
            &PyEventList::new(py, events.drain(..).map(PyEvent::new).collect::<Vec<_>>()),
        )?;

        Ok(Self { py, globals })
    }

    fn interactive(&self) -> PyResult<()> {
        let mut rl = DefaultEditor::new().expect("Could not create readline obj");

        let mut input = String::new();
        loop {
            let prefix = if input.is_empty() { ">>> " } else { "... " };

            let line = match rl.readline(prefix) {
                Ok(line) => line,
                Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
                Err(e) => {
                    println!("{e}");
                    continue;
                }
            };

            input.push_str(&line);

            match self.try_run(&input) {
                RunResult::Ok => {
                    rl.add_history_entry(input.as_str())
                        .expect("Couldn't add to history");
                    input.clear();
                }
                RunResult::Continue => {
                    input.push('\n');
                }
                RunResult::Err(e) => {
                    println!("{e}");
                    input.clear();
                }
            }
        }

        Ok(())
    }

    fn run(&self, script: &str) -> PyResult<()> {
        self.py
            .run_bound(script, Some(&self.globals.as_borrowed()), None)
    }

    fn try_run(&self, input: &str) -> RunResult {
        match self.run(input) {
            Ok(_) => RunResult::Ok,
            Err(e) => {
                if e.is_instance_of::<PySyntaxError>(self.py)
                    && unsafe {
                        pyo3::ffi::PyObject_IsInstance(
                            e.to_object(self.py).as_ptr(),
                            pyo3::ffi::PyExc_IndentationError,
                        )
                    } != 0
                {
                    return RunResult::Continue;
                }

                RunResult::Err(e)
            }
        }
    }
}

enum RunResult {
    Ok,
    Continue,
    Err(PyErr),
}
