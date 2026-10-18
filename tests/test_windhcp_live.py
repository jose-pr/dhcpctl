"""The Windows backend against a live Windows DHCP server, when one is named.

Opt-in: `DHCPCTL_WINDHCP_URI` names the server (`windhcp://host/?transport=ssh`,
with its credentials in the URI, `~/.ssh/config` or `DHCPCTL_WINDHCP_PASSWORD`),
`DHCPCTL_WINDHCP_NETWORK` a scope on it that serves no one (an inactive one),
and `DHCPCTL_WINDHCP_DNS` a name server that answers, because Windows refuses
one that does not. Each test arms, re-arms, keeps and removes one client with
the MAC 02:00:00:00:00:01 in that scope, reads the server back after each
step, and removes what it made even when it fails.
"""

from __future__ import annotations

import ipaddress
import json
import os

import pytest
from netimps import MACAddress

import dhcpctl

URI = os.environ.get("DHCPCTL_WINDHCP_URI")
NETWORK = os.environ.get("DHCPCTL_WINDHCP_NETWORK")
DNS = os.environ.get("DHCPCTL_WINDHCP_DNS")

pytestmark = pytest.mark.skipif(
    not (URI and NETWORK and DNS),
    reason="needs DHCPCTL_WINDHCP_URI, DHCPCTL_WINDHCP_NETWORK and DHCPCTL_WINDHCP_DNS",
)

#: What the server holds in the scope: reservations with their options, and
#: policies with theirs, as one JSON line.
STATE = [
    "$s = $p.ScopeId",
    "$state = @{ Reservations = @(); Policies = @() }",
    "foreach ($r in @(Get-DhcpServerv4Reservation -ScopeId $s)) {",
    "  $o = @{}; foreach ($v in @(Get-DhcpServerv4OptionValue -ReservedIP $r.IPAddress)) {",
    "    $o[[string]$v.OptionId] = @($v.Value) }",
    "  $state.Reservations += @{ Name = $r.Name; IP = [string]$r.IPAddress; Options = $o } }",
    "foreach ($q in @(Get-DhcpServerv4Policy -ScopeId $s -ErrorAction SilentlyContinue)) {",
    "  $o = @{}; foreach ($v in @(Get-DhcpServerv4OptionValue -ScopeId $s -PolicyName $q.Name)) {",
    "    $o[[string]$v.OptionId] = @($v.Value) }",
    "  $state.Policies += @{ Name = $q.Name; Order = $q.ProcessingOrder; Options = $o } }",
    "Write-Output ('STATE ' + ($state | ConvertTo-Json -Depth 5 -Compress))",
]


def _state(server, scope):
    output = server.run({"ScopeId": scope}, STATE)
    line = next(line for line in output.splitlines() if line.startswith("STATE "))
    return json.loads(line[6:])


@pytest.mark.parametrize("method", ["powershell", "netsh"])
def test_a_client_is_armed_re_armed_kept_and_removed(method):
    separator = "&" if "?" in URI else "?"
    password = os.environ.get("DHCPCTL_WINDHCP_PASSWORD")
    server = dhcpctl.connect(
        f"{URI}{separator}method={method}",
        secrets={"password": password} if password else None,
    )
    network = ipaddress.ip_network(NETWORK)
    scope = str(network.network_address)
    address = str(network.network_address + 10)
    codes = server.codes
    reservation = dhcpctl.Reservation(
        dhcpctl.Target("dhcpctl-live", mac=MACAddress("02:00:00:00:00:01")),
        dhcpctl.Scope("live", network=network),
        codes.lease(
            {
                "router": str(network.network_address + 1),
                "dns": [DNS],
                "file": "undionly.kpxe",
                "ip-forwarding": True,
                "time-offset": -3600,
            }
        ).replace(ip=address),
        conditions=dhcpctl.parse_conditions(
            {
                "ipxe": {
                    "match": {"user-class": "iPXE"},
                    "options": {"file": "boot.ipxe"},
                }
            },
            "live",
            codes,
        ),
        completion=dhcpctl.Completion(True, {"file": "sanboot.ipxe"}, codes=codes),
    )
    try:
        server.add(reservation)
        server.add(reservation)  # re-arming replaces it
        armed = _state(server, scope)
        (held,) = armed["Reservations"]
        assert held["IP"] == address
        options = held["Options"]
        assert options["6"] == [DNS] and options["19"] == ["0x01"]
        assert options["2"] == [str(-3600 % 2**32)]
        # The boot file is a policy's: on the reservation it would beat them.
        assert "67" not in options
        policies = {p["Name"]: p for p in armed["Policies"]}
        assert policies["dhcpctl-020000000001-ipxe"]["Options"]["67"] == ["boot.ipxe"]
        assert policies["dhcpctl-020000000001"]["Options"]["67"] == ["undionly.kpxe"]
        assert policies["dhcpctl-020000000001-ipxe"]["Order"] < (
            policies["dhcpctl-020000000001"]["Order"]
        )

        server.complete(reservation)
        kept = _state(server, scope)
        (held,) = kept["Reservations"]
        assert held["Options"]["67"] == ["sanboot.ipxe"] and kept["Policies"] == []
    finally:
        server.remove(reservation)
    assert _state(server, scope) == {"Reservations": [], "Policies": []}
