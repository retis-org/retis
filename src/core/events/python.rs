use std::{collections::HashMap, rc::Rc};

use pyo3::{
    exceptions::PyKeyError,
    prelude::{PyAnyMethods, PyListMethods},
    types::{PyList, PyString},
    *,
};

use crate::{
    core::events::{Event, EventDisplay},
    module::ModuleId,
};

/// Python representation of an Event.
///
/// We can't directly convert an Event to a Python representation because it
/// contains a map of trait implementation. We could just represent it as a
/// Python map, but using an object around it makes implementing custom methods
/// possible.
#[pyclass(unsendable)]
#[derive(Clone)]
pub(crate) struct PyEvent(Rc<Event>);

impl PyEvent {
    pub(crate) fn new(event: Event) -> Self {
        Self(Rc::new(event))
    }
}

impl ToPyObject for PyEvent {
    fn to_object(&self, py: Python<'_>) -> PyObject {
        self.clone().into_py(py)
    }
}

#[pymethods]
impl PyEvent {
    /// Controls how the PyEvent is represented, eg. what is the output of
    /// `print(e)`.
    fn __repr__<'a>(&'a self, py: Python<'a>) -> String {
        let raw = self.raw(py);
        let dict: &Bound<'_, PyAny> = raw.bind(py);
        dict.repr().unwrap().to_string()
    }

    /// Allows to use the object as a dictionary, eg. `e['skb']`.
    fn __getitem__<'a>(&'a self, py: Python<'a>, attr: &str) -> PyResult<Py<PyAny>> {
        if let Ok(id) = ModuleId::from_str(attr) {
            if let Some(section) = self.0.get(id) {
                return Ok(section.to_py(py));
            }
        }
        Err(PyKeyError::new_err(attr.to_string()))
    }

    /// Returns a dictionary with all key<>data stored (recursively) in the
    /// event, eg. `e.raw()['skb']['dev']`.
    fn raw(&self, py: Python<'_>) -> PyObject {
        to_pyobject(&self.0.to_json(), py)
    }

    /// Maps to our own logic to show the event, so we can print it like Retis
    /// would do in collect or print.
    fn show(&self) -> String {
        format!("{}", self.0.display(super::DisplayFormat::MultiLine))
    }
}

/// Python representation of a Vec<Event>.
///
/// Implementing our own object allows to provide custom methods.
#[pyclass]
#[derive(Clone)]
pub(crate) struct PyEventList(PyObject);

impl PyEventList {
    pub(crate) fn new(py: Python<'_>, elements: Vec<PyEvent>) -> Self {
        Self(PyList::new_bound(py, elements).into())
    }
}

#[pymethods]
impl PyEventList {
    /// Controls how the PyEventList is represented, eg. what is the output of
    /// `print(events)`.
    fn __repr__<'a>(&'a self, py: Python<'a>) -> PyResult<Bound<'a, PyString>> {
        let events: &Bound<'_, PyList> = self.0.downcast_bound::<PyList>(py).unwrap();
        events.repr()
    }

    /// Allows to use the object as a dictionary, eg. `events[0]`.
    fn __getitem__<'a>(&'a self, py: Python<'a>, attr: usize) -> PyResult<Bound<'a, PyAny>> {
        let events: &Bound<'_, PyList> = self.0.downcast_bound::<PyList>(py).unwrap();
        events.get_item(attr)
    }

    /// Allows to get the len of the object as a dictionary, eg. `len(events)`.
    fn __len__(&self, py: Python<'_>) -> usize {
        let events = self.0.downcast_bound::<PyList>(py).unwrap();
        events.len()
    }

    /// Returns a dictionary with all key<>data stored (recursively) in the
    /// event, eg. `events.raw()[0]['skb']['dev']`.
    fn raw(&self, py: Python<'_>) -> PyObject {
        let events = self.0.downcast_bound::<PyList>(py).unwrap();
        let mut list = Vec::new();

        for event in events.iter() {
            let raw = event.call_method("raw", (), None).unwrap();
            list.push(raw);
        }

        PyList::new_bound(py, list).into()
    }
}

impl ToPyObject for PyEventList {
    fn to_object(&self, py: Python<'_>) -> PyObject {
        self.clone().into_py(py)
    }
}

/// Converts a serde_json::Value to a PyObject.
pub(crate) fn to_pyobject(val: &serde_json::Value, py: Python<'_>) -> PyObject {
    use serde_json::Value;
    match val {
        Value::Null => py.None().into(),
        Value::Bool(b) => b.to_object(py),
        Value::Number(n) => n
            .as_i64()
            .map(|x| x.to_object(py))
            .or(n.as_u64().map(|x| x.to_object(py)))
            .or(n.as_f64().map(|x| x.to_object(py)))
            .expect("Cannot convert number to Python object"),
        Value::String(s) => s.to_object(py),
        Value::Array(a) => {
            let vec: Vec<_> = a.iter().map(|x| to_pyobject(x, py)).collect();
            vec.to_object(py)
        }
        Value::Object(o) => {
            let map: HashMap<_, _> = o.iter().map(|(k, v)| (k, to_pyobject(v, py))).collect();
            map.to_object(py)
        }
    }
}
