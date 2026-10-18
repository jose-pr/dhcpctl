"""How a script reaches PowerShell: whole, through the real local transport.

`WinDHCPBackend.run` on the `local` transport starts the same PowerShell
command line the `ssh` transport runs on the remote host, so these tests,
which run the real thing, also cover what ssh delivers. They need Windows
PowerShell; elsewhere they skip, saying why.
"""

from __future__ import annotations

import shutil
import sys

import pytest

import dhcpctl

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or shutil.which("powershell") is None,
    reason="needs Windows PowerShell",
)


@pytest.fixture
def local():
    return dhcpctl.connect("windhcp:///")


def test_a_multi_line_block_runs_whole(local):
    output = local.run(
        {"Items": ["a", "b", "c"]},
        ["foreach ($i in $p.Items) {", '  Write-Output "item $i"', "}"],
    )
    assert [line for line in output.splitlines() if line.startswith("item")] == [
        "item a",
        "item b",
        "item c",
    ]


def test_a_throw_after_a_block_fails_the_run(local):
    with pytest.raises(dhcpctl.ServerError, match="boom"):
        local.run(
            {}, ["foreach ($i in 1..2) {", "  Write-Output $i", "}", "throw 'boom'"]
        )


def test_a_failing_cmdlet_fails_the_run(local):
    with pytest.raises(dhcpctl.ServerError, match="Cannot find path"):
        local.run({}, ["Get-Item 'C:\\no\\such\\path'"])


def test_an_error_is_plain_text_not_clixml(local):
    with pytest.raises(dhcpctl.ServerError) as refused:
        local.run({}, ["throw 'plain'"])
    assert "CLIXML" not in str(refused.value) and "<Objs" not in str(refused.value)


def test_the_payload_arrives_as_data(local):
    hostile = "'; Write-Output 'injected'; '"
    output = local.run({"Name": hostile}, ["Write-Output $p.Name"])
    assert hostile in output and "\ninjected" not in output
