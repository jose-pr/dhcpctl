"""Executes the generated windhcp script in a real PowerShell, with netsh shimmed.

Every other windhcp test reads the script as text, which cannot catch a script
that does not do what it appears to: `& netsh @($c.Args)` *looks* like splatting
and is an array subexpression, so netsh receives one argument instead of twelve.
Running it is the only way to see that, so this module does.

Skips where PowerShell is absent (Linux and macOS CI); the DHCP commands
themselves are never run -- `netsh` is a function that records its arguments.
"""

import ipaddress
import json
import os
import shutil
import subprocess

import pytest
from netimps import MACAddress

import dhcpctl

POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")

pytestmark = pytest.mark.skipif(POWERSHELL is None, reason="needs PowerShell")

#: Replaces netsh with a function that logs its arguments one per line and
#: returns `$env:NETSH_FAIL_AT`'s call as a failure, then runs the real script.
HARNESS = """param([string]$Script)
$global:calls = 0
$global:applied = @()
function netsh {
    $i = $global:calls
    $global:calls++
    Add-Content -LiteralPath $env:NETSH_LOG -Value ("CALL " + ($args -join "|"))
    if ($args -contains "dump") {
        # With no NETSH_DUMP, report back exactly what was asked for: netsh did
        # as it was told, which is the normal case. A test that wants the
        # measured failure -- success reported, value dropped -- supplies its own.
        if ("$env:NETSH_DUMP" -ne "") {
            Get-Content -LiteralPath $env:NETSH_DUMP
        } else {
            $global:applied
        }
        $global:LASTEXITCODE = 0
        return
    }
    if ($args -contains "reservedoptionvalue") {
        # `$k`, not `$i`: `$i` is the call number the fail-at check below uses.
        $k = [array]::IndexOf($args, "reservedoptionvalue")
        $ip = $args[$k + 1]; $id = $args[$k + 2]; $kind = $args[$k + 3]
        $vals = ($args[($k + 4)..($args.Count - 1)] | ForEach-Object { '"' + $_ + '"' }) -join " "
        $global:applied += "Dhcp Server Scope set reservedoptionvalue $ip $id $kind $vals"
    }
    if ("$env:NETSH_FAIL_AT" -ne "" -and [int]$env:NETSH_FAIL_AT -eq $i) {
        $global:LASTEXITCODE = 1
    } else {
        $global:LASTEXITCODE = 0
    }
    "netsh output"
}
try {
    & ([scriptblock]::Create((Get-Content -Raw -LiteralPath $Script))) | Out-Null
    Write-Output "OK"
} catch {
    Write-Output ("THREW " + ($_.Exception.Message -replace '\\s+', ' '))
}
"""

#: What a client in 10.0.0.0/24 is served, with two name servers and no router.
OPTIONS = {
    "dns": ["10.0.0.53", "10.0.0.54"],
    "subnet-mask": "255.255.255.0",
    "broadcast-address": "10.0.0.255",
    "bootfile-name": "pxelinux.0",
}


def _reservation(name="web01", options=None):
    return dhcpctl.Reservation(
        dhcpctl.Target(
            name,
            mac=MACAddress("aa:bb:cc:dd:ee:ff"),
            hostname="web01",
        ),
        dhcpctl.Scope("lan", network=ipaddress.ip_network("10.0.0.0/24")),
        dhcpctl.PYDHCP_CODES.lease(OPTIONS if options is None else options).replace(
            ip="10.0.0.10"
        ),
    )


def _script(uri, action="add", name="web01", options=None):
    server = dhcpctl.connect(uri)
    captured = []
    server.run = lambda payload, body: captured.append(server.script_for(payload, body))
    getattr(server, action)(_reservation(name, options))
    return captured[0]


def _run(tmp_path, script, fail_at=None, dump=None):
    """Run `script` under the harness; return (verdict, [netsh arg lists])."""
    script_path = tmp_path / "script.ps1"
    # write_bytes, not write_text(newline=...): that keyword is 3.10+ and the
    # project floor is 3.9.
    script_path.write_bytes(script.encode("utf-8"))
    harness = tmp_path / "harness.ps1"
    harness.write_bytes(HARNESS.encode("utf-8"))
    log = tmp_path / "netsh.log"
    log.write_text("", encoding="utf-8")
    env = dict(os.environ, NETSH_LOG=str(log))
    env["NETSH_FAIL_AT"] = "" if fail_at is None else str(fail_at)
    if dump is None:
        env["NETSH_DUMP"] = ""
    else:
        dump_path = tmp_path / "dump.txt"
        dump_path.write_bytes(dump.encode("utf-8"))
        env["NETSH_DUMP"] = str(dump_path)
    completed = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(harness),
            "-Script",
            str(script_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert completed.returncode == 0, completed.stderr
    calls = [
        line[len("CALL ") :].split("|")
        for line in log.read_text(encoding="utf-8").splitlines()
        if line.startswith("CALL ")
    ]
    return completed.stdout.strip().splitlines()[-1], calls


def test_the_generated_script_runs_and_passes_each_argument_separately(tmp_path):
    # The regression this module exists for: one argument per element, so a
    # multi-valued option really is two addresses and not one token.
    verdict, calls = _run(tmp_path, _script("windhcp://dhcp01/?method=netsh"))
    assert verdict == "OK"
    # Re-arming first deletes the client's reservation, if any.
    assert calls[0][4:6] == ["delete", "reservedip"]
    assert calls[1][:6] == [
        "dhcp",
        "server",
        "scope",
        "10.0.0.0",
        "add",
        "reservedip",
    ]
    dns = [c for c in calls if "IPADDRESS" in c and "6" in c][0]
    assert dns[-2:] == ["10.0.0.53", "10.0.0.54"]


def test_a_remote_server_reaches_netsh_as_one_unc_argument(tmp_path):
    verdict, calls = _run(
        tmp_path, _script("windhcp://dhcp01/?method=netsh&server=dhcp02")
    )
    assert verdict == "OK"
    assert calls[0][2] == "\\\\dhcp02"


def test_a_failing_netsh_call_aborts_the_run_naming_the_command(tmp_path):
    verdict, calls = _run(
        tmp_path, _script("windhcp://dhcp01/?method=netsh"), fail_at=2
    )
    assert verdict.startswith("THREW")
    assert "set reservedoptionvalue" in verdict and "failed (1)" in verdict
    # It stops there rather than carrying on with a half-applied reservation.
    assert len(calls) == 3


def test_a_failing_delete_is_tolerated_so_cleanup_can_rerun(tmp_path):
    verdict, calls = _run(
        tmp_path,
        _script("windhcp://dhcp01/?method=netsh", action="remove"),
        fail_at=0,
    )
    assert verdict == "OK"
    assert calls[0][4:6] == ["delete", "reservedip"]


def test_a_hostile_value_arrives_as_one_argument_and_runs_nothing(tmp_path):
    # The payload is data: a value that looks like PowerShell must come out of
    # ConvertFrom-Json intact and reach netsh as a single argument.
    hostile = "web01'; Remove-Item C:\\ -Recurse #"
    script = _script("windhcp://dhcp01/?method=netsh", name=hostile)
    verdict, calls = _run(tmp_path, script)
    assert verdict == "OK"
    assert hostile in calls[1]


def test_the_cmdlet_script_also_parses_and_runs(tmp_path):
    # Same check for the default method: the cmdlets are shimmed away, so this
    # is about the script being valid PowerShell and the payload parsing.
    script = _script("windhcp://dhcp01/")
    harness = (
        "function Get-DhcpServerv4Reservation { }\n"
        "function Remove-DhcpServerv4Reservation { }\n"
        "function Add-DhcpServerv4Reservation { }\n"
        "function Set-DhcpServerv4OptionValue { }\n"
    ) + script
    path = tmp_path / "cmdlets.ps1"
    path.write_bytes(harness.encode("utf-8"))
    completed = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["ok"] is True


# -- the netsh read-back ----------------------------------------------------

#: What `netsh ... dump` really prints (captured from Windows Server 2025): one
#: command per option value, values quoted one token each, whatever the locale.
DUMP_TEMPLATE = (
    "Dhcp Server \\\\host Scope 10.0.0.0 Add reservedip 10.0.0.10 aabbccddeeff "
    '"web01" "dhcpctl" "BOTH"\n'
    "{options}"
)


def _dump(*options):
    lines = "".join(
        "Dhcp Server \\\\host Scope 10.0.0.0 set reservedoptionvalue 10.0.0.10 "
        f"{option_id} {kind} {values}\n"
        for option_id, kind, values in options
    )
    return DUMP_TEMPLATE.format(options=lines)


def _with_nameservers():
    return _script(
        "windhcp://dhcp01/?method=netsh",
        options=dict(OPTIONS, router="10.0.0.1"),
    )


def test_a_complete_dump_passes_verification(tmp_path):
    dump = _dump(
        ("3", "IPADDRESS", '"10.0.0.1"'),
        ("6", "IPADDRESS", '"10.0.0.53" "10.0.0.54"'),
        ("1", "IPADDRESS", '"255.255.255.0"'),
        ("28", "IPADDRESS", '"10.0.0.255"'),
        ("67", "STRING", '"pxelinux.0"'),
    )
    verdict, _ = _run(tmp_path, _with_nameservers(), dump=dump)
    assert verdict == "OK"


def test_an_option_missing_from_the_dump_fails_the_run(tmp_path):
    # netsh exited 0 for every command and the option is not there: exactly what
    # a rejected value looks like from outside.
    dump = _dump(
        ("3", "IPADDRESS", '"10.0.0.1"'),
        ("1", "IPADDRESS", '"255.255.255.0"'),
        ("28", "IPADDRESS", '"10.0.0.255"'),
        ("67", "STRING", '"pxelinux.0"'),
    )
    verdict, _ = _run(tmp_path, _with_nameservers(), dump=dump)
    assert verdict.startswith("THREW")
    assert "option 6 was not applied" in verdict


def test_a_dropped_value_fails_the_run(tmp_path):
    # The measured case: two name servers asked for, one kept, success reported.
    dump = _dump(
        ("3", "IPADDRESS", '"10.0.0.1"'),
        ("6", "IPADDRESS", '"10.0.0.53"'),
        ("1", "IPADDRESS", '"255.255.255.0"'),
        ("28", "IPADDRESS", '"10.0.0.255"'),
        ("67", "STRING", '"pxelinux.0"'),
    )
    verdict, _ = _run(tmp_path, _with_nameservers(), dump=dump)
    assert verdict.startswith("THREW")
    assert "option 6 kept 1 of 2 values" in verdict


def test_a_quoted_value_with_spaces_counts_as_one(tmp_path):
    # `15 STRING "my domain"` is one value, not two.
    script = _script(
        "windhcp://dhcp01/?method=netsh",
        options={
            "domain-name": "my domain",
            "subnet-mask": "255.255.255.0",
            "broadcast-address": "10.0.0.255",
            "bootfile-name": "pxelinux.0",
        },
    )
    dump = _dump(
        ("15", "STRING", '"my domain"'),
        ("1", "IPADDRESS", '"255.255.255.0"'),
        ("28", "IPADDRESS", '"10.0.0.255"'),
        ("67", "STRING", '"pxelinux.0"'),
    )
    verdict, _ = _run(tmp_path, script, dump=dump)
    assert verdict == "OK"
