# content of conftest.py

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--ovs-track", action="store_true", default=False, help="run ovs userspace tracking tests "
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--ovs-track"):
        # --ovs-track given in cli: do not skip slow tests
        return
    skip_ovs_track = pytest.mark.skip(reason="need --ovs-track option to run")
    for item in items:
        if "ovs_track" in item.keywords:
            item.add_marker(skip_ovs_track)
