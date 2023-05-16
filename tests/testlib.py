import json
import signal
import subprocess
import time
from os.path import dirname, abspath, join, getsize, exists
from shutil import rmtree
from tempfile import mkdtemp

import pytest
from pyroute2 import netns as ipnetns, NetNS


class Retis:
    """ Wrapper around retis command that allows tests to start collecting,
    execute whatever test, and finally stop the collector and retrieve the
    events for verification.
    """
    def __init__(self):
        self.binary = join(
            dirname(dirname(abspath(__file__))), "target", "debug", "retis"
        )
        self.tempdir = mkdtemp()
        self._events = []

    def _event_file(self):
        return join(self.tempdir, "events.json")

    def collect(self, *args):
        """ Run retis collect {ARGS}.
        Note that "--output" argument is automatically added so that events can
        then be parsed.
        """
        cmd = (
            [self.binary, "collect"] + list(args) + ["-o", self._event_file()]
        )
        print(f"running command: {cmd}")
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        time.sleep(5)

    def stop(self):
        """ Stop the running retis instance. """
        time.sleep(2)
        self.proc.send_signal(signal.SIGINT)
        try:
            outs, errs = self.proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            outs, errs = self.proc.communicate()

        print(
            "Command: '{}'. stdtout {}, stderr = {}".format(
                self.proc.args, outs, errs
            )
        )

        if exists(self._event_file()) and getsize(self._event_file()) > 0:
            with open(self._event_file()) as f:
                for event in f.readlines():
                    self._events.append(json.loads(event))

        rmtree(self.tempdir)

        return (outs.decode("utf8"), errs.decode("utf8"))

    def events(self):
        """ Return the events in a list of dictionaries. """
        return self._events


class NetworkNamespaces:
    """ Helper class that allows adding and removing network namespaces. """

    class Context:
        """ Context class that enters a namespace. """
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
        """ Create a network namespace with a given name. """
        self.ns[name] = NetNS(name)
        return self.ns[name]

    def get(self, name):
        """ Return the network namespace IPRoute2 handler. """
        return self.ns.get(name)

    def delete(self, name):
        """ Delete a namespace by name. """
        ns = self.ns.get(name)
        if ns:
            ns.close()

    def clear(self):
        """ Delete all namesaces. """
        for name in list(self.ns.keys()):
            ipnetns.remove(name)
            del self.ns[name]

    def run(self, name, *cmd):
        """ Run a command inside a namespace """
        with self.enter(name) as _:
            ret = run(cmd)
        return ret

    def enter(self, name):
        """ Enter a namepsace. Returns a context object to be used as:

            with Namespaces.enter("myns") as ipr:
                subprocess.run(["command", "run", "in", "namespace"])
                ipr.link() # IPRoute2 handler of the namespace
        """
        return NetworkNamespaces.Context(name, self.get(name))

@pytest.fixture
def netns():
    """Fixture that provides a NetworkNamespaces handler and clears it after
    execution of the test. """
    nsman = NetworkNamespaces()
    yield nsman
    nsman.clear()

class OVS:
    """ OVS handler class that is able to start a OVS instance, run multiple
    commands on it, and stop it.
    """
    def __init__(self, prefix="/usr"):
        self.ovs_vsctl = prefix + "/bin/ovs-vsctl"
        self.ovs_ofctl = prefix + "/bin/ovs-ofctl"
        self.ovs_appctl = prefix + "/bin/ovs-appctl"
        self.ovs_ctl = prefix + "/share/openvswitch/scripts/ovs-ctl"

    def start(self):
        """ Start openvswitch. """
        run([self.ovs_ctl, "--delete-bridges", "--system-id=random", "start"])

    def stop(self):
        """ Stop openvswitch. """
        for br in self.vsctl("list-br").split():
            self.vsctl("del-br", br)

        run([self.ovs_ctl, "stop"])

    def vsctl(self, *args):
        """ Run ovs-vsctl {args} """
        cmd = [self.ovs_vsctl] + list(args)
        ret = run(cmd)
        return ret.stdout.decode("utf8")

    def ofctl(self, *args):
        """ Run ovs-ofctl {args} """
        cmd = [self.ovs_ofctl] + list(args)
        ret = run(cmd)
        return ret.stdout.decode("utf8")

    def appctl(self, *args):
        """ Run ovs-appctl {args} """
        cmd = [self.ovs_appctl] + list(args)
        ret = run(cmd)
        return ret.stdout.decode("utf8")


@pytest.fixture
def ovs():
    """Fixture that provides starts OVS, provides a OVS handler and stops it
    after execution of the test. """
    ovs = OVS()
    ovs.start()
    yield ovs
    ovs.stop()

def run(cmd):
    ret = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ret.returncode != 0:
        pytest.fail(
            "Command: '{}' returned non-zero: {}. stdtout {}, stderr = {}".format(
                cmd,
                ret.returncode,
                ret.stdout.decode("utf8"),
                ret.stderr.decode("utf8"),
            )
        )
    return ret

