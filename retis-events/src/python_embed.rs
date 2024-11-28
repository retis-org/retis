use std::{
    ffi::{CStr, CString},
    fs,
    path::PathBuf,
};

use anyhow::Result;
use pyo3::{prelude::*, types::PyDict};

use super::python::*;

/// Create a python shell and execute the provided script.
pub fn shell_execute(file: PathBuf, script: Option<&PathBuf>) -> Result<()> {
    let event_file = PyEventFile::new(file)?;

    Python::with_gil(|py| -> PyResult<()> {
        let shell = PyShell::new(py, event_file)?;
        if let Some(script) = script {
            let script = fs::read_to_string(script)?;
            shell.run(&CString::new(script)?)
        } else {
            shell.interact()
        }
    })?;
    Ok(())
}

/// Python shell.
struct PyShell<'a> {
    py: Python<'a>,
    globals: Bound<'a, PyDict>,
}

impl<'a> PyShell<'a> {
    const INTERACTIVE_SHELL: &'static CStr = c"import code; code.interact(local=locals())";

    fn new(py: Python<'a>, file: PyEventFile) -> PyResult<Self> {
        let globals = PyDict::new(py);
        globals.set_item("reader", Py::new(py, file)?.into_bound(py))?;

        Ok(Self { py, globals })
    }

    fn run(&self, script: &CStr) -> PyResult<()> {
        self.py.run(script, Some(&self.globals.as_borrowed()), None)
    }

    fn interact(&self) -> PyResult<()> {
        self.run(Self::INTERACTIVE_SHELL)
    }
}
