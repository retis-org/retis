# retis

Python bindings for [retis](https://retis.readthedocs.io/en/stable/) events.

This python library can be used to read and post-process retis events.

Example:

```python
from retis import EventFile

reader = EventFile("retis.data")

for e in reader.events():
    print(e.show())
```
