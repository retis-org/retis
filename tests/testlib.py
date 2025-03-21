import json
import signal
import subprocess
import time
import re

from os import uname
from os.path import dirname, abspath, join, getsize, exists
from shutil import rmtree
from tempfile import mkdtemp

import pytest
from pyroute2 import netns as ipnetns, NetNS


class Retis:
    """Wrapper around retis command that allows tests to start collecting,
    execute whatever test, and finally stop the collector and retrieve the
    events for verification.
    """

    def __init__(self, target="debug"):
        self.binary = join(
            dirname(dirname(abspath(__file__))), "target", target, "retis"
        )
        self.tempdir = mkdtemp()
        self._events = []
        self._series = []
        self.target = target

    def __del__(self):
        rmtree(self.tempdir)

    def _event_file(self):
        return join(self.tempdir, "events.json")

    def _series_file(self):
        return join(self.tempdir, "series.json")

    def collect(self, *args):
        """Run retis collect {ARGS}.
        Note that "--output" argument is automatically added so that events can
        then be parsed.
        """
        cmd = [self.binary, "collect"] + list(args) + ["-o", self._event_file()]
        print(f"running command: {cmd}")
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        if self.target == "debug":
            # Debug builds take a long time to startup.
            time.sleep(7)

    def stop(self):
        """Stop the running retis instance."""
        time.sleep(2)
        self.proc.send_signal(signal.SIGINT)
        try:
            outs, errs = self.proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            outs, errs = self.proc.communicate()

        print(
            "Command: '{}'. stdtout {}, stderr = {}".format(self.proc.args, outs, errs)
        )

        if exists(self._event_file()) and getsize(self._event_file()) > 0:
            with open(self._event_file()) as f:
                for event in f.readlines():
                    self._events.append(json.loads(event))

        return (outs.decode("utf8"), errs.decode("utf8"))

    def events(self):
        """Return the events in a list of dictionaries."""
        return self._events

    def sort(self):
        """Run retis sort on the events and return the sorted events in a
        list."""
        result = []
        cmd = [self.binary, "sort"] + ["-o", self._series_file(), self._event_file()]
        print(f"running command: {cmd}")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        outs, errs = proc.communicate(timeout=15)

        print("Command: '{}'. stdtout {}, stderr = {}".format(proc, outs, errs))

        if exists(self._series_file()) and getsize(self._series_file()) > 0:
            with open(self._series_file()) as f:
                for series in f.readlines():
                    result.append(json.loads(series))

        return result

    def pcap(self, *args):
        """Run retis pcap {ARGS}. Always appends location of events file."""
        cmd = [self.binary, "pcap"] + list(args) + [self._event_file()]
        print(f"running command: {cmd}")
        try:
            result = subprocess.run(cmd, capture_output=True, check=True)
        except subprocess.CalledProcessError as e:
            raise Exception(
                "Failure running pcap subcommand\n"
                + f"cmd: {e.cmd}\n"
                + f"stdout: {e.stdout}\n"
                + f"stderr: {e.stderr}\n"
                + f"return code: {e.returncode}"
            )

        return result.stdout


class NetworkNamespaces:
    """Helper class that allows adding and removing network namespaces."""

    class Context:
        """Context class that enters a namespace."""

        def __init__(self, ns, handler):
            self.ns = ns
            self.handler = handler

        def __enter__(self):
            ipnetns.pushns(self.ns)
            return self.handler

        def __exit__(self, _exc_type, _exc_val, _exc_tb):
            ipnetns.popns()

    def __init__(self):
        self.ns = {}

    def add(self, name):
        """Create a network namespace with a given name."""
        self.ns[name] = NetNS(name)
        return self.ns[name]

    def get(self, name):
        """Return the network namespace IPRoute2 handler."""
        return self.ns.get(name)

    def delete(self, name):
        """Delete a namespace by name."""
        ns = self.ns.get(name)
        if ns:
            ns.close()

    def clear(self):
        """Delete all namesaces."""
        for name in list(self.ns.keys()):
            ipnetns.remove(name)
            del self.ns[name]

    def run(self, name, *cmd):
        """Run a command inside a namespace"""
        with self.enter(name) as _:
            ret = run(cmd)
        return ret

    def run_fail(self, name, *cmd):
        """Run a command inside a namespace that is expected to fail"""
        with self.enter(name) as _:
            ret = run(cmd, True)
        return ret

    def run_bg(self, name, *cmd):
        """Run a background command inside a namespace"""
        with self.enter(name) as _:
            ret = run_bg(cmd)
        return ret

    def enter(self, name):
        """Enter a namepsace. Returns a context object to be used as:

        with Namespaces.enter("myns") as ipr:
            subprocess.run(["command", "run", "in", "namespace"])
            ipr.link() # IPRoute2 handler of the namespace
        """
        return NetworkNamespaces.Context(name, self.get(name))


@pytest.fixture
def netns():
    """Fixture that provides a NetworkNamespaces handler and clears it after
    execution of the test."""
    nsman = NetworkNamespaces()
    yield nsman
    nsman.clear()


class OVS:
    """OVS handler class that is able to start a OVS instance, run multiple
    commands on it, and stop it.
    """

    def __init__(self, prefix="/usr"):
        self.ovs_vsctl = prefix + "/bin/ovs-vsctl"
        self.ovs_ofctl = prefix + "/bin/ovs-ofctl"
        self.ovs_appctl = prefix + "/bin/ovs-appctl"
        self.ovs_ctl = prefix + "/share/openvswitch/scripts/ovs-ctl"

    def start(self):
        """Start openvswitch."""
        run([self.ovs_ctl, "--delete-bridges", "--system-id=random", "start"])

    def stop(self):
        """Stop openvswitch."""
        for br in self.vsctl("list-br").split():
            self.vsctl("del-br", br)

        run([self.ovs_ctl, "stop"])

    def vsctl(self, *args):
        """Run ovs-vsctl {args}"""
        cmd = [self.ovs_vsctl] + list(args)
        ret = run(cmd)
        return ret.stdout.decode("utf8")

    def ofctl(self, *args):
        """Run ovs-ofctl {args}"""
        cmd = [self.ovs_ofctl] + list(args)
        ret = run(cmd)
        return ret.stdout.decode("utf8")

    def appctl(self, *args):
        """Run ovs-appctl {args}"""
        cmd = [self.ovs_appctl] + list(args)
        ret = run(cmd)
        return ret.stdout.decode("utf8")

    def version(self):
        """Run ovs-appctl {args}"""
        verstring = self.vsctl("--version").splitlines()[0]
        m = re.match(
            r"ovs-vsctl \(Open vSwitch\) ([0-9]*).([0-9]*).([0-9]*)", verstring
        )
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


@pytest.fixture
def ovs():
    """Fixture that provides starts OVS, provides a OVS handler and stops it
    after execution of the test."""
    ovs = OVS()
    ovs.start()
    yield ovs
    ovs.stop()


def run(cmd, should_fail=False):
    ret = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if (not should_fail and ret.returncode != 0) or (
        should_fail and ret.returncode == 0
    ):
        pytest.fail(
            "Command: '{}' returned: {}. stdtout {}, stderr = {}".format(
                cmd,
                ret.returncode,
                ret.stdout.decode("utf8"),
                ret.stderr.decode("utf8"),
            )
        )
    return ret


def run_bg(cmd):
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def assert_events_present(events, expected):
    """Asserts a list of expected events are present in the event list in the
    same order. The expected events can be specified as a subset of the event.
    """
    idx = 0
    aliases = {}
    for ex_idx, ex in enumerate(expected):
        found = False
        # Find an event that matches
        for i in range(idx, len(events)):
            (is_sub, reason) = is_subset(events[i], ex, aliases)
            if is_sub:
                print(
                    f"HIT: Event at index {i}\n"
                    f"   Event: {events[i]}\n"
                    f" matches expected at index {ex_idx}: \n"
                    f"   {ex}\n"
                    f"   Aliases: {aliases}"
                )
                found = True
                idx = i + 1
                break
            else:
                # Print the reason so it's easier to debug (if test fails)
                print(
                    f"MISS: Event at index {i}\n"
                    f"   Event {events[i]} \n"
                    f" did not match expected:"
                    f"   {ex}\n."
                    f"   Reason: {reason}."
                    f"   Aliases: {aliases}"
                )
        if not found:
            pytest.fail(
                f"Failed to find expected event at index >= {idx}:"
                f"   Expected: {ex}\n"
                f"   Aliases: {aliases}\n"
                f"   Event list {json.dumps(events, indent=4)}"
            )


def is_subset(superset, subset, aliases):
    """Recursively check if a dictionary is a subset of another one.

    Aliases are supported, if a value starts with '&' followed by an alias
    name, the value is stored in the provided hash table indexed by the alias
    name (no verification is made). If a value starts with '*' followed
    by an alias name, the value is retrieved from the aliases hash table
    and is checked. If a value starts with '!' followed by an alias name, the
    value is retrieved from the aliases hash table and is checked to make sure
    it does not match.

    E.g:
        > aliases = {}
        > is_subset(
            {"foo": {"bar": "helloWorld"}, "baz": 42},
            {"foo": {"bar": "&myalias"}, "baz": 42},
            aliases)
        >> True, None
        > is_subset(
            {"baz": "helloWorld"},
            {"baz": "*myalias"},
            aliases)
        >> True, None
    """
    for key, value in subset.items():
        if key not in superset:
            return (
                False,
                f"{subset} is not a subset of {superset}." f" key {key} is not present",
            )

        # Handle aliases
        if isinstance(value, str) and len(value) > 1 and value[0] == "&":
            # Store alias
            print(f"Saving value to aliases {value} -> {superset[key]}")
            aliases[value[1:]] = superset[key]
            continue
        if isinstance(value, str) and len(value) > 1 and value[0] == "*":
            # Load alias
            new_value = aliases.get(value[1:], None)
            print(f"Restoring value from aliases {value} -> {new_value}")
            value = new_value
        if isinstance(value, str) and len(value) > 1 and value[0] == "!":
            # Load alias & compare it does not match the current value
            old_value = aliases.get(value[1:], None)
            if old_value == superset[key]:
                return (False, f"{old_value} is equal to {superset[key]}")
            continue

        # Recursively assert nested dictionaries
        if isinstance(value, dict):
            (is_sub, reason) = is_subset(superset[key], value, aliases)
            if not is_sub:
                return (
                    False,
                    f"nested dictionary {value} is not a subset"
                    f" of {superset[key]}: {reason}",
                )
        # Allow substring matching
        elif isinstance(value, str):
            if value not in superset[key]:
                return (False, f"{value} is not contained in {superset[key]}")
        # Default to equality comparison
        else:
            if not value == superset[key]:
                return (False, f"{value} is not equal to {superset[key]}")
    return (True, None)


def kernel_version_lt(other):
    """Check if running kernel version is lower than the provided M.m.z
    version."""
    release = re.split(r"[.-]", uname().release)
    other = other.split(".", maxsplit=3)
    other = [other[i] if i < len(other) else 0 for i in range(3)]

    print(f"Running kernel: {release}")

    if release[0] != other[0]:
        return int(release[0]) < int(other[0])
    if release[1] != other[1]:
        return int(release[1]) < int(other[1])
    if release[2] != other[2]:
        return int(release[2]) < int(other[2])
