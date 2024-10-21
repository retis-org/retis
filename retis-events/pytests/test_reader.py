from retis import Event, EventFile, EventReader, EventSeries, SeriesReader

import pytest


def verify_event(e):
    """Verify the event is valid"""
    assert e.__class__ == Event
    assert isinstance(e.raw(), dict)
    assert isinstance(e.show(), str)
    assert "userspace" in e or "kernel" in e


def verify_event_reader(r):
    assert r.__class__ == EventReader
    for e in r:
        verify_event(e)


def verify_series_reader(r):
    assert r.__class__ == SeriesReader
    for s in r:
        assert s.__class__ == EventSeries
        length = len(s)
        i = 0

        for e in s:
            verify_event(e)
            i += 1

        assert i == length


def test_event_reader():
    """Test event reader is capable of reading valid events"""
    r = EventReader("test_data/test_events.json")
    verify_event_reader(r)


def test_series_reader():
    """Test SeriesReader is capable of reading sorted events"""
    r = SeriesReader("test_data/test_events_sorted.json")
    verify_series_reader(r)


def test_event_File():
    """Test EventFile is capable of reading reader is capable generating
    iterators"""
    f = EventFile("test_data/test_events.json")
    assert not f.sorted()
    verify_event_reader(f.events())

    with pytest.raises(Exception):
        f.series()

    sf = EventFile("test_data/test_events_sorted.json")
    assert sf.sorted()
    verify_series_reader(sf.series())

    with pytest.raises(Exception):
        sf.events()
