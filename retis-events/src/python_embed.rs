use std::{
    ffi::{CStr, CString},
    fs,
    path::PathBuf,
};

use anyhow::{anyhow, Result};
use pyo3::{prelude::*, types::PyDict};

use super::python::*;

/// Create a python shell and execute the provided script.
pub fn shell_execute(file: PathBuf, script: Option<&PathBuf>, args: &[String]) -> Result<()> {
    let event_file = PyEventFile::new(file)?;

    let argv = match script {
        Some(script) => {
            let mut argv = vec![script
                .clone()
                .into_os_string()
                .into_string()
                .map_err(|_| anyhow!("Could not convert script path to string"))?];
            argv.extend_from_slice(args);
            argv
        }
        None => Vec::new(),
    };

    Python::with_gil(|py| -> PyResult<()> {
        let shell = PyShell::new(py, event_file)?;
        if let Some(script) = script {
            let script = fs::read_to_string(script)?;
            shell.run(&CString::new(script)?, &argv)
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
    const INTERACTIVE_SHELL: &'static CStr = c"import code;
try:
    from scapy.all import *
except ImportError:
    pass

code.interact(local=locals())";

    fn new(py: Python<'a>, file: PyEventFile) -> PyResult<Self> {
        let globals = PyDict::new(py);
        globals.set_item("reader", Py::new(py, file)?.into_bound(py))?;

        Ok(Self { py, globals })
    }

    fn run(&self, script: &CStr, args: &[String]) -> PyResult<()> {
        let sys = self.py.import("sys")?;
        sys.setattr("argv", args)?;

        let globals = self.globals.clone();
        globals.set_item("sys", sys)?;

        self.py.run(script, Some(&globals.as_borrowed()), None)
    }

    fn interact(&self) -> PyResult<()> {
        self.run(Self::INTERACTIVE_SHELL, &[])
    }
}
