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
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys

import pytest

import dhcpctl

SESSION = pathlib.Path(__file__).parent / "peers" / "dhcpd_session.sh"
MAC = "aa:bb:cc:dd:ee:ff"
KEY = base64.b64encode(b"dhcpctl-test-key").decode("ascii")

#: One backend step, run inside the session with dhcpd up: argv[1] is add,
#: keep or remove, argv[2] the conditions mode.
STEP = """
import json
import sys
from netimps import MACAddress
import dhcpctl

action, mode = sys.argv[1], sys.argv[2]
# A third argument is the lease's options as JSON, instead of the default ones.
extra = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None
server = dhcpctl.connect(
    f"dhcpd://127.0.0.1:7911/?conditions={mode}",
    secrets={"keyname": "omapi_key", "omapi_key": %r},
)
codes = server.codes
lease = codes.lease(extra or {"router": "10.0.0.1", "file": "undionly.kpxe", "next-server": "10.0.0.2"})
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


def _session(tmp_path, *steps, options=None, ask=()) -> "list[dict[str, str]]":
    """Run `steps` against one dhcpd; what the client got at each lease step.

    `options` replaces the armed lease's options; the client also asks for
    each code in `ask`.
    """
    script = tmp_path / "step.py"
    script.write_text(STEP, encoding="utf-8")
    argv = ["unshare", "-rn", "sh", str(SESSION), MAC, KEY, str(tmp_path)]
    extra = "" if options is None else " " + shlex.quote(json.dumps(options))
    for step in steps:
        if step.startswith("lease") or step == "restart":
            argv.append(step)
        else:
            action, mode = step.split(":")
            argv.append(f"{sys.executable} {script} {action} {mode}{extra}")
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
    # The next server is gone; some udhcpc builds report dhcpd's own address.
    assert kept["boot_file"] == "sanboot.ipxe" and kept.get("siaddr") != "10.0.0.2"
    assert removed.get("ip") != "10.0.0.10" and "boot_file" not in removed


def test_arming_twice_replaces_the_host(tmp_path):
    (given,) = _session(tmp_path, "add:if", "add:if", "lease")
    assert given["ip"] == "10.0.0.10" and given["boot_file"] == "undionly.kpxe"


@pytest.mark.parametrize("mode", ["if", "group"])
def test_every_value_type_reaches_the_client_as_it_was_given(
    tmp_path, mode, value_types
):
    (given,) = _session(
        tmp_path,
        f"add:{mode}",
        "lease",
        options={name: value for name, value, *_ in value_types},
        ask=[code for _, _, code, *_ in value_types],
    )
    got = {var: given.get(var) for *_, var, _ in value_types}
    assert got == {var: expected for *_, var, expected in value_types}


def test_dhcpd_parses_every_option_it_is_given(tmp_path, every_option):
    # `dhcpd -t` checks a config without serving; a host per option, written as
    # the backend writes OMAPI statements, so one it cannot parse is named.
    from dhcpctl.backends._dhcpd import render_statements

    codes = dhcpctl.option_codes()
    lines = ["ddns-update-style none;", "subnet 10.0.0.0 netmask 255.255.255.0 {"]
    hosts = {}
    for code, value in every_option:
        try:
            statements = render_statements(codes.lease({f"option-{code}": value}))
        except dhcpctl.ConfigError:
            continue  # refused up front, which is the other acceptable answer
        hosts[len(lines) + 1] = (code, statements)
        mac = f"aa:bb:cc:dd:{code // 256:02x}:{code % 256:02x}"
        lines.append(f" host h{code} {{ hardware ethernet {mac}; {statements} }}")
    lines.append("}")
    conf = tmp_path / "dhcpd.conf"
    conf.write_text("\n".join(lines) + "\n", encoding="utf-8")
    checked = subprocess.run(
        ["dhcpd", "-t", "-cf", str(conf)], capture_output=True, text=True
    )
    refused = sorted(
        {
            hosts[int(line.split(" line ")[1].split(":")[0])]
            for line in (checked.stdout + checked.stderr).splitlines()
            if " line " in line
            and line.split(" line ")[1].split(":")[0].isdigit()
            and int(line.split(" line ")[1].split(":")[0]) in hosts
        }
    )
    assert len(hosts) > 100 and refused == []
    assert checked.returncode == 0, checked.stderr


@pytest.mark.parametrize("mode", ["if", "group"])
def test_what_was_armed_is_served_after_dhcpd_restarts(tmp_path, mode):
    # dhcpd writes an OMAPI host -- and a group -- to its leases file, which is
    # what keeps them; a dhcpd started on a fresh leases file has lost them.
    before, after, ipxe = _session(
        tmp_path, f"add:{mode}", "lease", "restart", "lease", "lease:iPXE"
    )
    assert before["boot_file"] == after["boot_file"] == "undionly.kpxe"
    assert after["ip"] == "10.0.0.10" and after["router"] == "10.0.0.1"
    assert ipxe["boot_file"] == "boot.ipxe"
