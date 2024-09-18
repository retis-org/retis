# Python bindings

Besides the basic post-processing commands provided by `retis` (e.g: `sort`),
python bindings exist to enable writing custom post-processing scripts.

These bindings can be used in two different ways: the built-in python
interpreter and the external python library.

## Overview

Python bindings currently provide the following basic python classes that
allow inspecting retis events:

- **Event**: Python representation of a retis event. It provides helpers to
access the event's sections and data within those sections.
- **EventSeries**: Python representation of a series of sorted events resulting
from the execution of `retis sort -o`. It implements the iterator protocol to
access the events.
- **EventReader**: Class capable of reading a file created by `retis collect`
and iterate over its events.
- **SeriesReader**: Class capable of reading a file created by `retis sort`
and iterate over the its series.
- **EventFile**: Reads an event file, determines whether it is sorted or not
and allow the creation of `EventReader` and `SeriesReader` instances.

More details can be found in the `retis_events` crate documentation.

## Builtin python interpreter

The builtin interpreter enables the execution of python scripts that can inspect
and further process retis events.

Within the script execution context, a global variable called `reader` is
available. It is of type `EventFile`.


```python
$ cat myscript.py
for event in reader.events():
    if "skb" in event and getattr(event["skb"], "tcp", None):
        print("TCP event with dport: {}".format(
            event["skb"].tcp.dport))

$ retis python myscript.py
```

If no script is provided, an interactive shell is created. Example:

```text
$ retis collect [...]
$ retis python
Python 3.12.6 (main, Sep  9 2024, 00:00:00) [GCC 14.2.1 20240801 (Red Hat 14.2.1-1)] on linux
Type "help", "copyright", "credits" or "license" for more information.
(InteractiveConsole)
>>> reader
<builtins.EventFile object at 0x7f1943606030>
>>> reader.sorted()
False
>>> events = reader.events()
>>> events 
<builtins.EventReader object at 0x7f44e17eaf60>
>>> print("Got {} events".format(sum(1 for _ in events)))
Got 783 events
```

The `EventFile` object available can also iterate through sorted files:

```text
$ retis collect [...]
$ retis sort -o sorted.data
$ retis python -i sorted.data
Python 3.12.6 (main, Sep  9 2024, 00:00:00) [GCC 14.2.1 20240801 (Red Hat 14.2.1-1)] on linux
Type "help", "copyright", "credits" or "license" for more information.
(InteractiveConsole)
>>> reader
<builtins.EventFile object at 0x7ffb50906130>
>>> reader.sorted()
True
>>> series = reader.series()
>>> series 
<builtins.SeriesReader object at 0x7f44e17e5b60>
>>> print("Got {} series".format(sum(1 for _ in series))
Got 149 series
```

## Python library

For more sophisticated programs that require more control over the python
environment (interpreter, dependencies, etc), a python library is available in
[pypi](https://pypi.org/retis). Unlike the builtin command, in this case the
`EventReader` or `SeriesReader` has to be be created manually.

```python
from retis import SeriesReader

import statistics

reader = SeriesReader("sorted_events.json")

events_per_series = [len(s) for s in reader]

print("Number of series: {}".format(len(events_per_series)))
print("Average events per series: {}".format(statistics.mean(events_per_series)))
```
