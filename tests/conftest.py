# content of conftest.py

import pytest

from testlib import NetworkNamespaces, OVS


@pytest.fixture
def netns():
    """Fixture that provides a NetworkNamespaces handler and clears it after
    execution of the test."""
    nsman = NetworkNamespaces()
    yield nsman
    nsman.clear()


@pytest.fixture
def ovs():
    """Fixture that provides starts OVS, provides a OVS handler and stops it
    after execution of the test."""
    ovs = OVS()
    ovs.start()
    yield ovs
    ovs.stop()


def pytest_addoption(parser):
    parser.addoption(
        "--ovs-track",
        action="store_true",
        default=False,
        help="run ovs userspace tracking tests ",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--ovs-track"):
        # --ovs-track given in cli: do not skip slow tests
        return
    skip_ovs_track = pytest.mark.skip(reason="need --ovs-track option to run")
    for item in items:
        if "ovs_track" in item.keywords:
            item.add_marker(skip_ovs_track)
