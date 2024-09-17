# retis

Python bindings for [retis](https://retis.readthedocs.io/en/stable/) events.

This python library can be used to read and post-process retis events.

Example:

```python
from retis import EventReader, Event

reader = EventReader("retis.data")

for event in reader:
    print(e.show())
```
