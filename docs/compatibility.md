# Compatibility

Retis exposes data and APIs in different ways, namely: when storing events at
collection time and in the Python API (built-in interpreter and library). This
page covers what is considered to be stable in terms of compatibility across
versions and what is not.

## Events file

When collecting events, Retis can store events in a file for later
post-processing (`retis.data` by default).

The event file format itself isn't guaranteed to be stable across time in any
way. It is not recommended to use it directly.

Starting with Retis `1.5.0` events collected and stored with a version of Retis
can be read with newer versions of Retis, across a given major version.

E.g. events collected with Retis v1.5.0 can be read with Retis v1.6.x, but might
not with Retis v2.y.x.

# Python API and events

Python can be used to post-process events. Both events and an API are exposed.
This is not considered stable across releases at the moment.
