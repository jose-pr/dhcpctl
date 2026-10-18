"""The dnsmasq backend against a real dnsmasq and a real DHCP client.

Each exchange starts dnsmasq on the files the backend wrote and asks for a
lease with busybox `udhcpc`, both inside network namespaces of the test's own
(`unshare -rn`), so nothing outside them is touched. It runs on Linux with
dnsmasq, udhcpc and unprivileged user namespaces; elsewhere it skips, saying
why, unless `DHCPCTL_REQUIRE_PEERS` is set, when a missing peer fails.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import dhcpctl

EXCHANGE = pathlib.Path(__file__).parent / "peers" / "dnsmasq_exchange.sh"
MAC = "aa:bb:cc:dd:ee:ff"


def _unavailable() -> "str|None":
    if not sys.platform.startswith("linux"):
        return "needs Linux network namespaces"
    for tool in ("dnsmasq", "udhcpc", "unshare", "nsenter", "ip"):
        if shutil.which(tool) is None:
            return f"needs {tool}"
    probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
    if probe.returncode != 0:
        return "needs unprivileged user namespaces (unshare -rn)"
    return None


@pytest.fixture(scope="module", autouse=True)
def peers():
    reason = _unavailable()
    if reason and os.environ.get("DHCPCTL_REQUIRE_PEERS"):
        pytest.fail(f"real-peer tests required, but this host {reason}")
    if reason:
        pytest.skip(reason)


def _lease(hosts, opts, tmp_path) -> "dict[str, str]":
    """What a client with MAC is handed by a dnsmasq reading hosts and opts."""
    out = tmp_path / "out"
    subprocess.run(
        ["unshare", "-rn", "sh", str(EXCHANGE), str(hosts), str(opts), MAC, str(out)],
        check=True,
        timeout=60,
    )
    text = out.read_text(encoding="utf-8")
    given, _, log = text.partition("--- dnsmasq\n")
    for line in log.splitlines():
        # dnsmasq reports a line it cannot parse and goes on without it.
        assert "bad" not in line and "error" not in line.lower(), log
    if given.strip() == "NO-LEASE":
        return {}
    return dict(line.split("=", 1) for line in given.splitlines() if "=" in line)


@pytest.fixture(params=["directory", "file"])
def server(request, tmp_path):
    hosts, opts = tmp_path / "hosts", tmp_path / "opts"
    if request.param == "directory":
        hosts.mkdir()
        opts.mkdir()
        # Each exchange starts a dnsmasq of its own, so there is none to signal.
        uri = (
            f"dnsmasq:///?hostsfile={hosts.as_posix()}/&optsfile={opts.as_posix()}/"
            "&reload=true"
        )
    else:
        uri = (
            f"dnsmasq:///?hostsfile={hosts.as_posix()}&optsfile={opts.as_posix()}"
            "&reload=true"
        )
    return dhcpctl.connect(uri), hosts, opts


def test_an_armed_client_gets_its_address_and_boot_file(server, reservation, tmp_path):
    backend, hosts, opts = server
    backend.add(
        reservation(
            backend,
            {"file": "undionly.kpxe", "router": "10.0.0.1"},
            next_server="10.0.0.2",
        )
    )
    lease = _lease(hosts, opts, tmp_path)
    assert lease.get("ip") == "10.0.0.10"
    assert lease.get("boot_file") == "undionly.kpxe"
    assert lease.get("siaddr") == "10.0.0.2"
    assert lease.get("router") == "10.0.0.1"
    assert lease.get("hostname") == "web01"


def test_a_kept_client_keeps_its_address_and_loses_its_boot_file(
    server, reservation, tmp_path
):
    backend, hosts, opts = server
    armed = reservation(
        backend,
        {"file": "undionly.kpxe", "router": "10.0.0.1"},
        next_server="10.0.0.2",
        completion={"keep": True},
    )
    backend.add(armed)
    backend.complete(armed)
    lease = _lease(hosts, opts, tmp_path)
    assert lease.get("ip") == "10.0.0.10"
    assert lease.get("router") == "10.0.0.1"
    assert "boot_file" not in lease and "bootfile" not in lease


TWICE = pathlib.Path(__file__).parent / "peers" / "dnsmasq_twice.sh"

#: Completes web01 on the dnsmasq URI in argv[1], keeping it when argv[2] is
#: "keep"; run between two exchanges with the same dnsmasq.
COMPLETE = """
import sys
import dhcpctl
from netimps import MACAddress
server = dhcpctl.connect(sys.argv[1])
lease = server.codes.lease({"file": "undionly.kpxe"}).replace(ip="10.0.0.10", strict=False)
completion = dhcpctl.Completion(keep=sys.argv[2] == "keep")
server.complete(
    dhcpctl.Reservation(
        dhcpctl.Target("web01", mac=MACAddress("aa:bb:cc:dd:ee:ff")),
        lease=lease,
        completion=completion,
    )
)
"""


@pytest.mark.parametrize("keep", ["remove", "keep"])
def test_a_running_dnsmasq_stops_serving_what_completion_took_away(
    reservation, tmp_path, keep
):
    # --dhcp-hostsdir and --dhcp-optsdir only ever add what they read: a
    # removed or rewritten file keeps being served until dnsmasq gets SIGHUP.
    hosts, opts, pid = tmp_path / "hosts", tmp_path / "opts", tmp_path / "dnsmasq.pid"
    hosts.mkdir()
    opts.mkdir()
    uri = (
        f"dnsmasq:///?hostsfile={hosts.as_posix()}/&optsfile={opts.as_posix()}/"
        f"&pidfile={pid.as_posix()}"
    )
    backend = dhcpctl.connect(uri)
    backend.add(reservation(backend, {"file": "undionly.kpxe"}))
    script = tmp_path / "complete.py"
    script.write_text(COMPLETE, encoding="utf-8")
    first, second = tmp_path / "out1", tmp_path / "out2"
    subprocess.run(
        ["unshare", "-rn", "sh", str(TWICE), str(hosts), str(opts), MAC, str(pid)]
        + [str(first), str(second), sys.executable, str(script), uri, keep],
        check=True,
        timeout=90,
    )
    before = _given(first)
    after = _given(second)
    assert (
        before.get("ip") == "10.0.0.10" and before.get("boot_file") == "undionly.kpxe"
    )
    assert "boot_file" not in after, after
    if keep == "keep":
        assert after.get("ip") == "10.0.0.10"
    else:
        assert after.get("ip") != "10.0.0.10"


def _given(out) -> "dict[str, str]":
    given, _, _ = out.read_text(encoding="utf-8").partition("--- dnsmasq\n")
    if given.strip() == "NO-LEASE":
        return {}
    return dict(line.split("=", 1) for line in given.splitlines() if "=" in line)


def test_a_removed_client_is_not_reserved(server, reservation, tmp_path):
    backend, hosts, opts = server
    armed = reservation(backend, {"file": "undionly.kpxe"})
    backend.add(armed)
    backend.complete(armed)
    lease = _lease(hosts, opts, tmp_path)
    # A client with no reservation is offered an address from the range.
    assert lease.get("ip") != "10.0.0.10"
    assert "boot_file" not in lease
