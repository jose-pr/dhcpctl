"""The Kea backend against a real Kea and a real DHCP client.

Each test starts kea-dhcp4 (with the host_cmds and class_cmds hooks, and no
hosts database) behind kea-ctrl-agent on 127.0.0.1:8000, inside network
namespaces of its own (`unshare -rn`), arms, keeps and removes a client through
the backend between DHCP exchanges, and reads what the client was given. It
runs on Linux with Kea, udhcpc, requests and unprivileged user namespaces;
elsewhere it skips, saying why, unless `DHCPCTL_REQUIRE_PEERS` is set.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys

import pytest

SESSION = pathlib.Path(__file__).parent / "peers" / "kea_session.sh"
MAC = "aa:bb:cc:dd:ee:ff"
#: Reservations go into Kea's running configuration: it has no hosts database.
URI = "kea://127.0.0.1:8000/?target=memory"

#: One backend step, run inside the session with Kea up: argv[1] is add, keep
#: or remove; a second argument is the lease's options as JSON.
STEP = """
import json
import sys
from ipaddress import ip_network
from netimps import MACAddress
import dhcpctl

server = dhcpctl.connect(%r)
codes = server.codes
options = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {
    "router": "10.0.0.1", "file": "undionly.kpxe", "next-server": "10.0.0.2"
}
conditions = dhcpctl.parse_conditions(
    {"ipxe": {"match": {"user-class": "iPXE"}, "options": {"file": "boot.ipxe"}}}, "t", codes
)
reservation = dhcpctl.Reservation(
    dhcpctl.Target("web01", mac=MACAddress(%r)),
    scope=dhcpctl.Scope("lan", network=ip_network("10.0.0.0/24")),
    lease=codes.lease(options).replace(ip="10.0.0.10"),
    conditions=conditions if len(sys.argv) <= 2 else {},
    completion=dhcpctl.Completion(True, {"file": "sanboot.ipxe"}, codes=codes),
)
{"add": server.add, "keep": server.complete, "remove": server.remove}[sys.argv[1]](reservation)
""" % (URI, MAC)


def _unavailable() -> "str|None":
    if not sys.platform.startswith("linux"):
        return "needs Linux network namespaces"
    for tool in ("kea-dhcp4", "kea-ctrl-agent", "udhcpc", "unshare", "nsenter", "ip"):
        if shutil.which(tool) is None:
            return f"needs {tool}"
    if not pathlib.Path("/usr/lib64/kea/hooks/libdhcp_host_cmds.so").exists():
        return "needs Kea's host_cmds hook"
    if importlib.util.find_spec("requests") is None:
        return "needs the 'kea' extra (requests)"
    if subprocess.run(["unshare", "-rn", "true"], capture_output=True).returncode:
        return "needs unprivileged user namespaces (unshare -rn)"
    return None


@pytest.fixture(scope="module", autouse=True)
def peers():
    reason = _unavailable()
    if reason and os.environ.get("DHCPCTL_REQUIRE_PEERS"):
        pytest.fail(f"real-peer tests required, but this host {reason}")
    if reason:
        pytest.skip(reason)


def _session(tmp_path, *steps, options=None, ask=()) -> "list[dict[str, str]]":
    """Run `steps` against one Kea; what the client got at each lease step."""
    script = tmp_path / "step.py"
    script.write_text(STEP, encoding="utf-8")
    argv = ["unshare", "-rn", "sh", str(SESSION), MAC, str(tmp_path)]
    extra = "" if options is None else " " + shlex.quote(json.dumps(options))
    for step in steps:
        if step.startswith("lease"):
            argv.append(step)
        else:
            argv.append(f"{sys.executable} {script} {step}{extra}")
    env = dict(os.environ, ASK=" ".join(str(code) for code in ask))
    subprocess.run(argv, check=True, timeout=120, env=env)
    leases = []
    for n in range(1, sum(s.startswith("lease") for s in steps) + 1):
        text = (tmp_path / f"lease{n}").read_text(encoding="utf-8")
        if text.strip() == "NO-LEASE":
            leases.append({})
        else:
            leases.append(dict(line.split("=", 1) for line in text.splitlines()))
    return leases


def test_arm_keep_and_remove_reach_the_client(tmp_path):
    armed, ipxe, kept, removed = _session(
        tmp_path, "add", "lease", "lease:iPXE", "keep", "lease:iPXE", "remove", "lease"
    )
    assert armed["ip"] == "10.0.0.10" and armed["boot_file"] == "undionly.kpxe"
    assert armed["siaddr"] == "10.0.0.2" and armed["router"] == "10.0.0.1"
    # The condition: an iPXE client is handed the script instead.
    assert ipxe["ip"] == "10.0.0.10" and ipxe["boot_file"] == "boot.ipxe"
    # Kept: the address and router stay, the boot file is the completion's.
    assert kept["ip"] == "10.0.0.10" and kept["router"] == "10.0.0.1"
    assert kept["boot_file"] == "sanboot.ipxe"
    assert removed.get("ip") != "10.0.0.10" and "boot_file" not in removed


def test_arming_twice_replaces_the_reservation(tmp_path):
    plain, ipxe = _session(tmp_path, "add", "add", "lease", "lease:iPXE")
    assert plain["ip"] == "10.0.0.10" and plain["boot_file"] == "undionly.kpxe"
    assert ipxe["boot_file"] == "boot.ipxe"


def test_every_value_type_reaches_the_client_as_it_was_given(tmp_path, value_types):
    (given,) = _session(
        tmp_path,
        "add",
        "lease",
        options={name: value for name, value, *_ in value_types},
        ask=[code for _, _, code, *_ in value_types],
    )
    got = {var: given.get(var) for *_, var, _ in value_types}
    assert got == {var: expected for *_, var, expected in value_types}
