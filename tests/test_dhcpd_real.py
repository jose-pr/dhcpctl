"""The dhcpd backend against a real ISC dhcpd over OMAPI, and a real client.

Each test starts dhcpd with OMAPI on 127.0.0.1:7911 inside network namespaces
of its own (`unshare -rn`), arms, keeps and removes a client through the
backend between DHCP exchanges, and reads what the client was given. It runs
on Linux with dhcpd, udhcpc, pypureomapi and unprivileged user namespaces;
elsewhere it skips, saying why, unless `DHCPCTL_REQUIRE_PEERS` is set.
"""

from __future__ import annotations

import base64
import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

SESSION = pathlib.Path(__file__).parent / "peers" / "dhcpd_session.sh"
MAC = "aa:bb:cc:dd:ee:ff"
KEY = base64.b64encode(b"dhcpctl-test-key").decode("ascii")

#: One backend step, run inside the session with dhcpd up: argv[1] is add,
#: keep or remove, argv[2] the conditions mode.
STEP = """
import sys
from netimps import MACAddress
import dhcpctl

action, mode = sys.argv[1], sys.argv[2]
server = dhcpctl.connect(
    f"dhcpd://127.0.0.1:7911/?conditions={mode}",
    secrets={"keyname": "omapi_key", "omapi_key": %r},
)
codes = server.codes
lease = codes.lease({"router": "10.0.0.1", "file": "undionly.kpxe", "next-server": "10.0.0.2"})
conditions = dhcpctl.parse_conditions(
    {"ipxe": {"match": {"user-class": "iPXE"}, "options": {"file": "boot.ipxe"}}}, "t", codes
)
reservation = dhcpctl.Reservation(
    dhcpctl.Target("web01", mac=MACAddress(%r)),
    lease=lease.replace(ip="10.0.0.10"),
    conditions=conditions,
    completion=dhcpctl.Completion(True, {"file": "sanboot.ipxe"}, codes=codes),
)
{"add": server.add, "keep": server.complete, "remove": server.remove}[action](reservation)
""" % (KEY, MAC)


def _unavailable() -> "str|None":
    if not sys.platform.startswith("linux"):
        return "needs Linux network namespaces"
    for tool in ("dhcpd", "udhcpc", "unshare", "nsenter", "ip"):
        if shutil.which(tool) is None:
            return f"needs {tool}"
    if importlib.util.find_spec("pypureomapi") is None:
        return "needs the 'dhcpd' extra (pypureomapi)"
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


def _session(tmp_path, *steps) -> "list[dict[str, str]]":
    """Run `steps` against one dhcpd; what the client got at each lease step."""
    script = tmp_path / "step.py"
    script.write_text(STEP, encoding="utf-8")
    argv = ["unshare", "-rn", "sh", str(SESSION), MAC, KEY, str(tmp_path)]
    for step in steps:
        if step.startswith("lease"):
            argv.append(step)
        else:
            action, mode = step.split(":")
            argv.append(f"{sys.executable} {script} {action} {mode}")
    subprocess.run(argv, check=True, timeout=120)
    leases = []
    for n in range(1, sum(s.startswith("lease") for s in steps) + 1):
        text = (tmp_path / f"lease{n}").read_text(encoding="utf-8")
        if text.strip() == "NO-LEASE":
            leases.append({})
        else:
            leases.append(dict(line.split("=", 1) for line in text.splitlines()))
    return leases


@pytest.mark.parametrize("mode", ["if", "group"])
def test_arm_keep_and_remove_reach_the_client(tmp_path, mode):
    armed, ipxe, kept, removed = _session(
        tmp_path,
        f"add:{mode}",
        "lease",
        "lease:iPXE",
        f"keep:{mode}",
        "lease:iPXE",
        f"remove:{mode}",
        "lease",
    )
    assert armed["ip"] == "10.0.0.10" and armed["boot_file"] == "undionly.kpxe"
    assert armed["siaddr"] == "10.0.0.2" and armed["router"] == "10.0.0.1"
    # The condition: an iPXE client is handed the script instead.
    assert ipxe["ip"] == "10.0.0.10" and ipxe["boot_file"] == "boot.ipxe"
    # Kept: the address and router stay, the boot file is the completion's,
    # and the condition is gone with the installer's boot file.
    assert kept["ip"] == "10.0.0.10" and kept["router"] == "10.0.0.1"
    assert kept["boot_file"] == "sanboot.ipxe" and "siaddr" not in kept
    assert removed.get("ip") != "10.0.0.10" and "boot_file" not in removed


def test_arming_twice_is_refused_not_overwritten(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        _session(tmp_path, "add:if", "add:if")
