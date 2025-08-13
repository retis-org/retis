# Python bindings

Besides the basic post-processing commands provided by `retis` (e.g: `sort`),
python bindings exist to enable writing custom post-processing scripts.

These bindings can be used in two different ways: the built-in python
interpreter and the external python library.

## Requirements

Python >= 3.7 is required. In order to build retis on older distros where
this python version is not available, please run:

```
$ CARGO_CMD_OPTS="--no-default-features" make
```

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
and iterate over the series.
- **EventFile**: Reads an event file, determines whether it is sorted or not
and allow the creation of `EventReader` and `SeriesReader` instances.

More details can be found in the `retis-events` crate documentation.

## Builtin python interpreter

The builtin interpreter enables the execution of python scripts that can inspect
and further process retis events.

Within the script execution context, a global variable called `reader` is
available. It is of type `EventFile`.


```python
$ cat myscript.py
for event in reader.events():
    if event.kernel:
        print("event from {}".format(event.kernel.symbol))

$ retis python myscript.py
```

Python scripts can be stored in `$HOME/.config/retis/python` or
`/usr/share/retis/python` and executed using their name:

```text
$ ls $HOME/.config/retis/python
foo.py
$ retis python foo
...
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

### Command line arguments

When executing a script using `retis python script.py`, command line arguments
are available in `sys.argv`. Modules like `argparse` can be used as-is.

```text
$ cat argv.py
print(sys.argv)
$ retis python argv.py
['argv.py']
$ retis python argv.py foo
['argv.py', 'foo']
$ retis python -- argv.py -x --foo
['argv.py', '-x', '--foo']
```

## Python library

For more sophisticated programs that require more control over the python
environment (interpreter, dependencies, etc), a python library is available in
[pypi](https://pypi.org/project/retis). Unlike the builtin command, in this case
the `EventReader` or `SeriesReader` has to be be created manually.

```python
from retis import SeriesReader

import statistics

reader = SeriesReader("sorted_events.json")

events_per_series = [len(s) for s in reader]

print("Number of series: {}".format(len(events_per_series)))
print("Average events per series: {}".format(statistics.mean(events_per_series)))
```

## Parsing the packet data

The packet itself is stored as raw data in the Retis events and as such
individual packet fields cannot be directly accessed. A third party library is
required, such as (Scapy)[https://scapy.readthedocs.io/].

To ease packet consumption a helper is available to convert raw packets to a
Scapy `Ether` representation. The helper only works if Scapy is available on the
system.

Example after launching the builtin interpreter (`retis python`):

```text
$ retis python
>>> events = reader.events()
>>> e = next(events) # Skip startup event
>>> e = next(events)
>>> p = e.packet.to_scapy()
>>> print(p.summary())
Ether / IP / TCP 1.1.1.1:https > 10.0.0.42:12345 A
>>> if IP in p:
...     print("src: " + p[IP].src)
...
src: 1.1.1.1
>>> if TCP in p:
...     p[TCP].options(2)
...
('Timestamp', (3570509991, 2706919))
```

While not mandatory for using `to_scapy()`, to access the full Scapy
functionalities its objects must be imported first when using the Retis Python
library or when executing a Python script (Scapy is automatically imported when
using the builtin interpreter).

```python
from scapy.all import *
```

The raw packet data can also be accessed as a bytes string or as bytes, for
low-level access or for using in other packet-parsing libraries:

```python
e.packet.data          # Bytes string
bytes(e.packet.data)   # bytes

# Manual implementation of to_scapy().
from scapy.layers.l2 import Ether
Ether(bytes(e.packet.data))
```

## Available helpers

Different helpers and built-in methods are provided to help working with events
in Python.

With the top-level event:

```text
>>> print(event.sections())
['ct', 'skb-tracking', 'common', 'skb', 'kernel']
>>> event.to_dict().keys()  # Makes the event and all its sub-sections a real dict.
dict_keys(['skb-tracking', 'kernel', 'common', 'ct', 'skb'])
>>> event.to_dict()['common'].keys()
dict_keys(['timestamp'])
```

With the top-level event and all sections:

```text
>>> print(event)
8974965787422 (5) [ping] 100854 [tp] net:net_dev_start_xmit #829a5a5cb1effff8be0ca834000 (skb ffff8be0ca56ae00)
  if 3 (eth0)
  xx:xx:xx:xx:xx:xx > xx:xx:xx:xx:xx:xx ethertype IPv4 (0x0800) 10.0.42.5 > 1.1.1.1 tos 0x0 ttl 64 id 2368 off 0 [DF] len 84 proto ICMP (1) type 8 code 0
  ct_state NEW status 0x188 icmp orig [10.0.42.5 > 1.1.1.1 type 8 code 0 id 1] reply [1.1.1.1 > 10.0.42.5 type 0 code 0 id 1] zone 0 mark 0
>>> print(event.common)
8974965787422 (5) [ping] 100854
>>> print(event.ct)
ct_state NEW status 0x188 icmp orig [10.0.42.5 > 1.1.1.1 type 8 code 0 id 1] reply [1.1.1.1 > 10.0.42.5 type 0 code 0 id 1] zone 0 mark 0
>>> print(repr(e.common))   # Or just `e.common` in any Python REPL (e.g. the built-in interpreter).
{'task': {'comm': 'irq/184-iwlwifi', 'tgid': 1632, 'pid': 1632}, 'smp_id': 7, 'timestamp': 6876861762597}
```

With the `skb-tracking` section:

```text
>>> hex(event.skb_tracking.tracking_id())
'0x829a5a5cb1effff8be0ca834000'
>>> e0.skb_tracking.match(e1.skb_tracking)        # Match on the tracking id.
True
>>> e0.skb_tracking.strict_match(e1.skb_tracking) # Match on the tracking id + skb address.
False
```

With the `packet` sub-section in the `skb` section:

```text
>>> event.packet.to_scapy()
...
```
