from retis import Event, EventFile

import pytest


def test_event_inspection():
    """Test Event sections can be accessed"""
    f = EventFile("test_data/test_events.json")
    events = f.events()

    # Skip startup event
    next(events)

    e = next(events)

    # Access via getitem and contains
    assert "kernel" in e
    assert "userspace" not in e
    assert "foo" not in e
    assert e["kernel"]

    with pytest.raises(KeyError):
        assert e["userspace"]

    # Direct access
    assert e.kernel
    assert e.userspace is None

    # Sections
    sections = e.sections()
    assert isinstance(e.sections(), list)
    assert "kernel" in e.sections()
    assert "userspace" not in e.sections()
    assert "foo" not in e.sections()
