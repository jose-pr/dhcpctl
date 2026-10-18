"""Windows DHCP Server backend: its cmdlets or netsh, locally, over ssh or WinRM.

Windows DHCP has no line protocol to speak, so this backend drives the server's own
tooling where the operator already has access. Two independent choices:

- **`transport=`** -- how we get a shell, through hostctl: `local` (this
  machine), `ssh` or `winrm`. hostctl delivers the PowerShell script whole and
  reports its status, on every transport.
- **`method=`** -- what we run there: `powershell` (the `DhcpServer` module's
  cmdlets, the default) or `netsh` (`netsh dhcp server ...`), for a host where
  the DHCP Server PowerShell module is not installed -- a Server Core box
  without the RSAT feature, or an older release.

The transport and the DHCP server stay separate either way: the shell runs on the
URI's host, and the commands act on `server=` (`-ComputerName`, or netsh's
`\\server`) when that differs. `transport=local` plus `server=dhcp01` is therefore
the ordinary RSAT shape -- run PowerShell here, act on that server -- and the one
an operator's own workstation is already set up for. An empty host
(`windhcp:///?server=dhcp01`) means local, because there is no host to reach.

**A reservation's options outrank every policy.** Microsoft's order is
reservation > scope policy > server policy > scope > server, and the rule is per
option: a client that got option 67 from its reservation *ignores* option 67 from
any policy. So an option a condition overrides must **not** be written on the
reservation, or the condition is dead on arrival -- and this is invisible in the
server's configuration, which is why it has to be a rule in the code rather than
something to notice later.

That leaves two shapes, and `conditions=` picks:

* **`target`** (default) -- one policy per target per condition, matched on the
  target's **MAC** plus the condition's test, and a base policy matched on the MAC
  alone carrying what the overridden options would have been. Precise, works with
  per-target boot files, and needs no rights beyond those a reservation already
  needs, because the backend creates the policies itself.
* **`shared`** -- one policy per condition name, matched on the test alone, for
  every client in the scope. The overridden options are still omitted from the
  reservation, but the *base* value for them is then not this backend's to serve:
  it comes from a scope option or another policy. This is the shape for a host
  where policies cannot be created from here at all (**netsh has no policy verb**), because an
  administrator can create one policy per condition once rather than one per
  machine forever.

**No value is ever interpolated into the script.** The parameters travel as a
JSON payload that PowerShell parses, with one escaping rule applied once (a
single-quoted PowerShell string escapes `'` by doubling it). Values arrive as
data, not as source.

That holds for `method=netsh` too, and it is why netsh is invoked *from*
PowerShell rather than from a command line: each netsh argument stays an element
of a JSON array and is passed through `&  netsh @args`, so no quoting rule has to
hold for a value. PowerShell is present on every Windows that has netsh, so this
costs nothing and removes the whole command-line quoting question.
"""

from __future__ import annotations

import json as _json
import logging
import os as _os
import re as _re
import subprocess as _subprocess
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from netimps import MACAddress
from pydhcp.options import I32, U8, U16, U32, Boolean, IPv4AddressOption
from pydhcp.options import List as CodecList

from .._conditions import Condition
from .._model import Reservation, Target
from .._options import DHCPLease, DHCPOptionCode, DHCPOptions, plain_items
from .._server import DEFAULT_OWNER, DHCPServer, Secrets
from ..exceptions import (
    BackendUnavailableError,
    ConditionMissingError,
    ConfigError,
    ServerError,
)

__all__ = ["WinDHCPBackend"]

LOGGER = logging.getLogger("dhcpctl")

#: Codes left off a Windows reservation: Windows defines no option 119 unless
#: an administrator adds it, and setting an undefined option aborts the script.
_SKIPPED = frozenset({DHCPOptionCode.DOMAIN_SEARCH})

#: pydhcp item codec -> the data type `netsh ... set reservedoptionvalue` wants.
#: The cmdlets infer it from the option definition; netsh does not, and stores an
#: address told `STRING` wrongly without complaint. Anything else is STRING.
_NETSH_TYPES = (
    (IPv4AddressOption, "IPADDRESS"),
    (U32, "DWORD"),
    (I32, "DWORD"),
    (U16, "WORD"),
    (U8, "BYTE"),
    (Boolean, "BYTE"),
)


def _netsh_type(code: Any) -> str:
    """netsh's data type for `code`, a member of the bag's codemap."""
    codec = code.get_type()
    if issubclass(codec, CodecList):
        codec = codec.item_type()
    for base, name in _NETSH_TYPES:
        if issubclass(codec, base):
            return name
    return "STRING"


#: Runs each `Commands` entry as `netsh <args...>`. The arguments stay array
#: elements -- never a string PowerShell re-parses -- so a value cannot become
#: syntax. netsh's own text goes to the log; its **exit code** is what decides,
#: because the success line ("Command completed successfully.") is localised and
#: matching it would break on a non-English host. `Ignore` is for a delete that
#: may have nothing to delete, so cleanup can re-run.
#: netsh exits 0 and prints its localised success line even when it rejected
#: what it was told: setting option 6 to two name servers, one of which does not
#: answer, drops that one, says "not a valid DNS Server", says "Command completed
#: successfully", and exits 0 (measured on Windows Server 2025, 2026-10-02). So
#: the end state is read back instead of trusted. `dump` is the one netsh output
#: that is machine-readable and not prose -- it emits the commands that would
#: recreate the state, quoted one token per value, in any locale.
_NETSH_VERIFY = [
    "if ($p.Verify) {",
    "  $d = @($p.VerifyArgs)",
    '  $dump = (& netsh @d 2>&1 | Out-String) -split "`r?`n"',
    "  $bad = @()",
    "  foreach ($v in $p.Verify) {",
    "    $re = 'set reservedoptionvalue\\s+' + [regex]::Escape($p.IPAddress) +",
    "          '\\s+' + $v.Id + '\\s'",
    "    $line = $dump | Where-Object { $_ -match $re } | Select-Object -First 1",
    '    if (-not $line) { $bad += "option $($v.Id) was not applied"; continue }',
    "    $tail = $line -replace ('^.*' + $re), ''",
    "    $tail = $tail -replace '^\\S+\\s*', ''",
    '    $n = @([regex]::Matches($tail, \'"[^"]*"|\\S+\')).Count',
    "    if ($n -lt $v.Count) {",
    '      $bad += "option $($v.Id) kept $n of $($v.Count) values"',
    "    }",
    "  }",
    "  if ($bad) {",
    '    throw "netsh reported success but the server disagrees: " +',
    "          ($bad -join '; ')",
    "  }",
    "}",
]

_NETSH_BODY = [
    "foreach ($c in $p.Commands) {",
    # `@a` on a *variable* is splatting, one argument per element. `@($c.Args)`
    # is an array subexpression -- it passes the whole array as one argument,
    # which netsh then sees as a single space-filled token. Measured by running
    # the generated script with a shim in place of netsh.
    "  $a = @($c.Args)",
    "  $out = & netsh @a 2>&1 | Out-String",
    "  Write-Verbose $out",
    "  if ($LASTEXITCODE -ne 0 -and -not $c.Ignore) {",
    "    throw \"netsh $($c.Args -join ' ') failed ($LASTEXITCODE): $out\"",
    "  }",
    "}",
]

_SCRIPT = """$ErrorActionPreference = 'Stop'
$p = ConvertFrom-Json '{payload}'
{body}
ConvertTo-Json @{{ ok = $true }}
"""


#: What `_SCRIPT` prints last; output without it means the script did not finish.
_FINISHED = _re.compile(r'"ok"\s*:\s*true')

#: Thrown by the policy script when the host has no `DhcpServer` module, so the
#: Python side can turn it into a `ConditionMissingError` carrying the recipe. A
#: marker rather than a message match: the cmdlets' own errors are localised.
#: Prefixed with the owner, upper-cased.
_NO_POLICY_CMDLETS = "NO-POLICY-CMDLETS"

#: Creates the policy if it is absent, then sets its option values. Windows
#: policies are **scope-level and matched by condition, not by member list**, so
#: every target naming the same `dhcp_when` key converges on one policy -- which
#: is why this is create-if-absent rather than create.
#:
#: `-Condition AND` is used even for a single test, because a policy with two
#: conditions and no operator is rejected; AND is also the documented meaning of
#: "all of these must match", which is what a multi-key `match` says.
_POLICY_BODY = [
    # netsh has **no policy verb at all** -- measured on Windows Server 2025,
    # 2026-10-03: neither `netsh dhcp server scope <s> ?` nor `netsh dhcp server ?`
    # lists one. Policies arrived with the DhcpServer module after netsh was
    # frozen, so they are cmdlet-only whatever `method=` says, and a host without
    # the module cannot have them created from here at all.
    "$cmdlets = [bool](Get-Command Add-DhcpServerv4Policy -ErrorAction SilentlyContinue)",
    # A shared policy is the estate's: where it cannot even be looked up, it is
    # trusted to exist, as the operator was told to create it.
    "if (-not $cmdlets -and -not $p.Shared) {",
    "  throw '{marker}'",
    "}",
    "foreach ($pol in $(if ($cmdlets) { $p.Policies } else { @() })) {",
    "  $common = @{}",
    "  if ($p.ComputerName) { $common['ComputerName'] = $p.ComputerName }",
    "  $existing = Get-DhcpServerv4Policy -ScopeId $p.ScopeId -Name $pol.Name"
    " @common -ErrorAction SilentlyContinue",
    # Shared: it exists -- use it, and change nothing about it.
    "  if ($existing -and $p.Shared) { continue }",
    # A policy references a user/vendor class **by name**, and Windows refuses
    # one that is not defined on the server: "The specified User class iPXE does
    # not exist on DHCP server" (measured on Server 2025, 2026-10-03). So the
    # class comes first, and is itself create-if-absent -- an estate that already
    # defines `iPXE` keeps its own definition.
    "  foreach ($cls in $pol.Classes) {",
    "    $have = Get-DhcpServerv4Class -Name $cls.Name -Type $cls.Type @common"
    " -ErrorAction SilentlyContinue",
    "    if (-not $have) {",
    "      Add-DhcpServerv4Class -Name $cls.Name -Type $cls.Type -Data $cls.Data"
    " @common",
    "    }",
    "  }",
    "  if (-not $existing) {",
    "    $new = @{ Name = $pol.Name; ScopeId = $p.ScopeId; Condition = 'AND' }",
    "    if ($pol.UserClass)   { $new['UserClass']   = @('EQ', $pol.UserClass) }",
    "    if ($pol.VendorClass) { $new['VendorClass'] = @('EQ', $pol.VendorClass) }",
    # The MAC is what scopes a policy to one target. Without it a policy answers
    # every client in the scope that matches the test.
    "    if ($pol.MacAddress)  { $new['MacAddress']  = @('EQ', $pol.MacAddress) }",
    "    Add-DhcpServerv4Policy @new @common",
    "  }",
    # Processing order decides which policy answers a client that matches several:
    # the conditional one must be consulted before the base one, or a target's
    # chainload never happens. Windows assigns an order by creation, and this says
    # it rather than relying on it.
    "  if ($pol.Order) {",
    "    Set-DhcpServerv4Policy -Name $pol.Name -ScopeId $p.ScopeId"
    " -ProcessingOrder $pol.Order @common",
    "  }",
    "  foreach ($o in $pol.Options) {",
    "    Set-DhcpServerv4OptionValue -PolicyName $pol.Name -ScopeId $p.ScopeId"
    " -OptionId $o.Id -Value $o.Value @common",
    "  }",
    "}",
]


class WinDHCPBackend(DHCPServer):
    """`windhcp://[user@]host/?transport=local|ssh|winrm&method=powershell|netsh&server=<dhcp server>`

    The scope comes from the reservation, not from here. The account and WinRM's password are the
    `user` and `password` secrets: the URI's, else the caller's.
    """

    SETTINGS = frozenset(
        {
            "transport",
            "method",
            "server",
            "auth",
            "port",
            "ssl",
            "conditions",
            "timeout",
        }
    )

    def __init__(
        self,
        uri: str,
        *,
        secrets: Secrets = None,
        owner: str = DEFAULT_OWNER,
        codes: Any = None,
    ) -> None:
        super().__init__(uri, secrets=secrets, owner=owner, codes=codes)
        parts = urlsplit(uri)
        self.hostname = parts.hostname or "localhost"
        # No host to reach means the shell is here. Only an *empty* host: a named
        # one that happens to be this machine still goes through its transport,
        # because guessing otherwise surprises whoever wrote the name.
        default_transport = "local" if not parts.hostname else "ssh"
        self.transport = self.settings.get("transport", default_transport)
        if self.transport not in ("local", "ssh", "winrm"):
            raise ConfigError(
                f"windhcp: transport must be local, ssh or winrm, not "
                f"{self.transport!r}"
            )
        if self.transport == "local" and _os.name != "nt":
            raise ConfigError(
                "windhcp: transport=local needs Windows PowerShell and the "
                "DhcpServer module on this machine; use ssh or winrm to reach a "
                "host that has them"
            )
        self.conditions = str(self.settings.get("conditions", "target")).lower()
        if self.conditions not in ("target", "shared"):
            raise ConfigError(
                f"windhcp: conditions must be target or shared, not "
                f"{self.conditions!r}"
            )
        self.method = str(self.settings.get("method", "powershell")).lower()
        if self.method not in ("powershell", "netsh"):
            raise ConfigError(
                f"windhcp: method must be powershell or netsh, not {self.method!r}"
            )
        self.server = self.settings.get("server") or ""
        self.auth = self.settings.get("auth", "ntlm")
        try:
            self.port = (
                int(self.settings["port"]) if self.settings.get("port") else None
            )
            #: Seconds one script may run, `timeout=` (default 120).
            self.timeout = float(self.settings.get("timeout") or 120)
        except ValueError as exc:
            raise ConfigError(f"windhcp: port and timeout are numbers: {exc}") from exc
        self.ssl = str(self.settings.get("ssl", "")).lower() in ("1", "true", "yes")

    @property
    def user(self) -> str:
        """The account the shell runs as: the `user` secret, or `""`."""
        return self.secret("user") or ""

    # -- the DHCPServer contract ------------------------------------------

    def add(self, reservation: Reservation) -> None:
        # Conditions first: a policy must exist before a reservation can rely on
        # it, and a failure here must not leave a half-armed client behind.
        self._apply_conditions(reservation, reservation.conditions.values())
        if self.method == "netsh":
            self._add_netsh(reservation)
            return
        target = reservation.target
        options = _served(reservation.lease)
        _warn_dropped(reservation.lease)
        overridden = self._overridden_ids(reservation.conditions.values())
        payload = {
            "ScopeId": _scope(reservation),
            "IPAddress": _address(reservation),
            "ClientId": _client_id(target),
            "Name": str(target.name),
            "ComputerName": self.server,
            # A list, never a comma-joined string: `Set-DhcpServerv4OptionValue
            # -Value` takes String[], and refuses "a,b" with "Parameters for
            # option value to be set for option ID 6 do not match with option
            # definition" -- which, under $ErrorActionPreference='Stop', also
            # abandoned every option after it. Measured against a real Windows
            # Server 2025 DHCP server, 2026-10-02.
            # Omit anything a condition overrides: a reservation option beats
            # every policy, so writing it here would make the condition dead.
            "Options": [
                {"Id": option_id, "Value": [str(v) for v in _values(value)]}
                for option_id, value in _option_ids(options)
                if option_id not in overridden
            ],
        }
        body = [
            "$common = @{}",
            "if ($p.ComputerName) { $common['ComputerName'] = $p.ComputerName }",
            # Re-arming replaces the client's reservation, and its options with it.
            "$existing = Get-DhcpServerv4Reservation -ScopeId $p.ScopeId @common"
            " -ErrorAction SilentlyContinue |"
            " Where-Object { $_.ClientId -eq $p.ClientId }",
            "if ($existing) {",
            "  Remove-DhcpServerv4Reservation -ScopeId $p.ScopeId"
            " -ClientId $p.ClientId @common",
            "}",
            "Add-DhcpServerv4Reservation -ScopeId $p.ScopeId -IPAddress $p.IPAddress"
            " -ClientId $p.ClientId -Name $p.Name @common",
            "foreach ($o in $p.Options) {",
            "  Set-DhcpServerv4OptionValue -ReservedIP $p.IPAddress -OptionId $o.Id"
            " -Value $o.Value @common",
            "}",
        ]
        body.extend(_script_lines(self.extras(reservation, "add")))
        self.run(payload, body)

    def remove(self, reservation: Reservation) -> None:
        if self.method == "netsh":
            self._remove_netsh(reservation)
            self._remove_policies(reservation, reservation.conditions.values())
            return
        target = reservation.target
        payload = {
            "ScopeId": _scope(reservation),
            "ClientId": _client_id(target),
            "ComputerName": self.server,
        }
        body = [
            "$common = @{}",
            "if ($p.ComputerName) { $common['ComputerName'] = $p.ComputerName }",
            # Removing a reservation that is not there is success: cleanup re-runs.
            "$existing = Get-DhcpServerv4Reservation -ScopeId $p.ScopeId @common"
            " -ErrorAction SilentlyContinue |"
            " Where-Object { $_.ClientId -eq $p.ClientId }",
            "if ($existing) {",
            "  Remove-DhcpServerv4Reservation -ScopeId $p.ScopeId"
            " -ClientId $p.ClientId @common",
            "}",
        ]
        body.extend(_script_lines(self.extras(reservation, "remove")))
        self.run(payload, body)
        self._remove_policies(reservation, reservation.conditions.values())

    # -- completion (keep the reservation, drop the boot options) ----------

    def keep(self, reservation: Reservation) -> None:
        """Leave the reservation, replacing or removing its boot options.

        `Remove-DhcpServerv4OptionValue` per option id rather than touching the
        reservation: the address, its name and every other option stay exactly as
        they were, which is the point of keeping it.
        """
        options = _served(reservation.completion.apply_to(reservation.lease))
        applied = dict(_option_ids(_served(reservation.lease)))
        wanted = dict(_option_ids(options))
        _warn_dropped(reservation.completion.apply_to(reservation.lease))
        if self.method == "netsh":
            self._keep_netsh(reservation, options, applied, wanted)
            return
        payload = {
            "ScopeId": _scope(reservation),
            "IPAddress": _address(reservation),
            "ComputerName": self.server,
            "Set": [
                {"Id": option_id, "Value": [str(v) for v in _values(value)]}
                for option_id, value in wanted.items()
            ],
            "Remove": [option_id for option_id in applied if option_id not in wanted],
        }
        body = [
            "$common = @{}",
            "if ($p.ComputerName) { $common['ComputerName'] = $p.ComputerName }",
            "foreach ($o in $p.Set) {",
            "  Set-DhcpServerv4OptionValue -ReservedIP $p.IPAddress -OptionId $o.Id"
            " -Value $o.Value @common",
            "}",
            "foreach ($id in $p.Remove) {",
            # Already absent is success: completion re-runs, and an operator may
            # have cleared it by hand.
            "  Remove-DhcpServerv4OptionValue -ReservedIP $p.IPAddress -OptionId $id"
            " @common -ErrorAction SilentlyContinue",
            "}",
        ]
        body.extend(_script_lines(self.extras(reservation, "remove")))
        self.run(payload, body)

    # -- conditions (scope-level policies) ---------------------------------

    def _policy_name(self, target: Target, suffix: str = "") -> str:
        """The policy name for this client (or this client's base policy)."""
        if self.conditions == "shared":
            return suffix
        prefix = f"{self.owner}-{_netsh_client_id(target)}"
        return f"{prefix}-{suffix}" if suffix else prefix

    def _apply_conditions(
        self, reservation: Reservation, conditions: Iterable[Condition]
    ) -> None:
        """Create or reuse the policies serving this target's conditions.

        In `target` mode there is one policy per condition, matched on the MAC as
        well as the test, plus a **base** policy matched on the MAC alone carrying
        what the overridden options would have been -- because those options are
        kept off the reservation, where they would have outranked every policy.
        """
        conditions = list(conditions)
        if not conditions:
            return
        payload = {
            "ScopeId": _scope(reservation),
            "ComputerName": self.server,
            "Shared": self.conditions == "shared",
            "Policies": self._policies(reservation, conditions),
        }
        marker = f"{self.owner.upper()}-{_NO_POLICY_CMDLETS}"
        body = [line.replace("{marker}", marker) for line in _POLICY_BODY]
        try:
            self.run(payload, body)
        except Exception as exc:  # noqa: BLE001 - transport errors vary
            if marker not in str(exc):
                raise
            # Step 3 of the ladder: it cannot be created from here, so hand over
            # what someone with the module (RSAT anywhere, `-ComputerName` this
            # server) must run once. After that, arming needs none of this.
            raise ConditionMissingError(
                f"{self.hostname} has no DhcpServer PowerShell module, and netsh "
                f"has no policy support at all, so {self.owner} cannot create the "
                f"policy for "
                f"{', '.join('dhcp_when.' + c.name for c in conditions)}. Run this "
                f"once as a DHCP administrator, from any host with RSAT:",
                self._recipe(reservation, conditions),
            ) from exc

    def _policies(
        self, reservation: Reservation, conditions: List[Condition]
    ) -> List[Dict[str, Any]]:
        """The policies that serve these conditions to this target, in order."""
        target = reservation.target
        mac = "" if self.conditions == "shared" else _netsh_client_id(target)
        policies = []
        order = 1
        for condition in conditions:
            policies.append(
                {
                    "Name": self._policy_name(target, condition.name),
                    "UserClass": condition.match.get("user-class", ""),
                    "VendorClass": condition.match.get("vendor-class", ""),
                    "MacAddress": mac,
                    "Order": order,
                    "Classes": _classes_for(condition),
                    "Options": [
                        {"Id": option_id, "Value": [str(v) for v in _values(value)]}
                        for option_id, value in _option_ids(_served(condition.lease))
                    ],
                }
            )
            order += 1
        base = self._base_policy(reservation, conditions, mac, order)
        if base is not None:
            policies.append(base)
        return policies

    def _overridden_ids(self, conditions: Iterable[Condition]) -> Set[int]:
        """Option ids these conditions override, which the reservation must not set.

        A reservation's option outranks every policy's (reservation > scope policy
        > server policy > scope > server, per option), so leaving one of these on
        the reservation would silently kill the condition.
        """
        ids = set()
        for condition in conditions:
            ids.update(
                option_id for option_id, _ in _option_ids(_served(condition.lease))
            )
        return ids

    def _base_policy(
        self,
        reservation: Reservation,
        conditions: List[Condition],
        mac: str,
        order: int,
    ) -> Optional[Dict[str, Any]]:
        """The policy serving the overridden options when no condition matches.

        Only in `target` mode: it is matched on the MAC alone, so it is this
        client's own fallback. In `shared` mode there is nothing this backend can
        safely write -- a scope-wide base policy would answer for every client --
        so the operator provides it (a scope option, or a policy of their own) and
        this returns None.
        """
        if self.conditions == "shared":
            return None
        overridden = self._overridden_ids(conditions)
        if not overridden:
            return None
        options = _served(reservation.lease)
        values = [
            {"Id": option_id, "Value": [str(v) for v in _values(value)]}
            for option_id, value in _option_ids(options)
            if option_id in overridden
        ]
        if not values:
            return None
        return {
            "Name": self._policy_name(reservation.target),
            "UserClass": "",
            "VendorClass": "",
            "MacAddress": mac,
            "Order": order,
            "Classes": [],
            "Options": values,
        }

    def remove_condition_member(
        self, reservation: Reservation, condition: Condition
    ) -> None:
        """Remove this target's own policies; never a shared one.

        In `target` mode the policies belong to this target and go with it. In
        `shared` mode the policy is the estate's, and removing it would break every
        other target that names the same condition.
        """
        self._remove_policies(reservation, [condition])

    def _remove_policies(
        self, reservation: Reservation, conditions: Iterable[Condition]
    ) -> None:
        """Remove this target's policies for `conditions`, and its base policy.

        Only in `target` mode, and only what this target created: a removed
        client's MAC-matched policies would go on answering it.
        """
        conditions = list(conditions)
        if self.conditions == "shared" or not conditions:
            return
        target = reservation.target
        names = [self._policy_name(target, c.name) for c in conditions]
        payload = {
            "ScopeId": _scope(reservation),
            "ComputerName": self.server,
            "Names": names + [self._policy_name(target)],
        }
        body = [
            "$common = @{}",
            "if ($p.ComputerName) { $common['ComputerName'] = $p.ComputerName }",
            # Without the module no policy could have been made from here.
            "if (Get-Command Remove-DhcpServerv4Policy -ErrorAction SilentlyContinue) {",
            "  foreach ($n in $p.Names) {",
            # Already gone is success: completion re-runs.
            "    Remove-DhcpServerv4Policy -Name $n -ScopeId $p.ScopeId @common"
            " -ErrorAction SilentlyContinue",
            "  }",
            "}",
        ]
        self.run(payload, body)

    def ensure_condition(self, reservation: Reservation, condition: Condition) -> str:
        """Windows can create its own policies, so this is create-if-absent.

        `add` does every condition in one script rather than one round trip
        each; this is for a caller that wants just one.
        """
        self._apply_conditions(reservation, [condition])
        return condition.name

    def condition_recipe(self, reservation: Reservation, condition: Condition) -> str:
        """The PowerShell an admin runs to create this policy by hand.

        netsh cannot create a policy, and an operator without DHCP-admin rights
        cannot create one at all -- in both cases this is what they hand to
        someone who can. It is built from the same policies `add` applies, so
        in `target` mode it names this target's MAC-matched pair. Every value is
        a quoted literal.
        """
        return self._recipe(reservation, [condition])

    def _recipe(self, reservation: Reservation, conditions: List[Condition]) -> str:
        server = f" -ComputerName {_ps_quote(self.server)}" if self.server else ""
        names = ", ".join(repr(c.name) for c in conditions)
        lines = [
            f"# {self.owner}: create the DHCP policies for {names} once, as an admin",
            f"$scope = {_ps_quote(_scope(reservation))}",
        ]
        for policy in self._policies(reservation, conditions):
            name = _ps_quote(policy["Name"])
            for cls in policy["Classes"]:
                # Without the class the policy cannot be created at all.
                cname = _ps_quote(cls["Name"])
                lines.append(
                    f"if (-not (Get-DhcpServerv4Class -Name {cname} "
                    f"-Type {cls['Type']}{server} -ErrorAction SilentlyContinue)) {{ "
                    f"Add-DhcpServerv4Class -Name {cname} -Type {cls['Type']} "
                    f"-Data {_ps_quote(cls['Data'])}{server} }}"
                )
            args = [f"-Name {name}", "-ScopeId $scope", "-Condition AND"]
            for key, flag in (
                ("UserClass", "-UserClass"),
                ("VendorClass", "-VendorClass"),
                ("MacAddress", "-MacAddress"),
            ):
                if policy[key]:
                    args.append(f"{flag} EQ,{_ps_quote(policy[key])}")
            lines.append("Add-DhcpServerv4Policy " + " ".join(args) + server)
            if self.conditions == "target":
                lines.append(
                    f"Set-DhcpServerv4Policy -Name {name} -ScopeId $scope "
                    f"-ProcessingOrder {int(policy['Order'])}{server}"
                )
            for option in policy["Options"]:
                rendered = ",".join(_ps_quote(v) for v in option["Value"])
                lines.append(
                    f"Set-DhcpServerv4OptionValue -PolicyName {name} -ScopeId $scope "
                    f"-OptionId {int(option['Id'])} -Value {rendered}{server}"
                )
        return "\n".join(lines)

    # -- method=netsh ------------------------------------------------------

    def _netsh_scope(self, scope: str) -> List[str]:
        """The `dhcp server [\\host] scope <scope>` prefix every command shares."""
        prefix = ["dhcp", "server"]
        if self.server:
            # netsh addresses a remote server as a UNC-style name; it accepts an
            # address too, which is why this is not validated as a hostname.
            prefix.append(
                self.server if self.server.startswith("\\\\") else f"\\\\{self.server}"
            )
        prefix += ["scope", scope]
        return prefix

    def _add_netsh(self, reservation: Reservation) -> str:
        target = reservation.target
        options = _served(reservation.lease)
        _warn_dropped(reservation.lease)
        scope = _scope(reservation)
        base = self._netsh_scope(scope)
        commands = [
            {
                # Re-arming replaces the client's reservation; none is fine.
                "Args": base
                + [
                    "delete",
                    "reservedip",
                    _address(reservation),
                    _netsh_client_id(target),
                ],
                "Ignore": True,
            },
            {
                # `add reservedip <ip> <mac> [name] [comment] [BOTH|DHCP|BOOTP]`.
                # BOTH matches the cmdlets' default, so switching method does not
                # change which protocols the reservation answers.
                "Args": base
                + [
                    "add",
                    "reservedip",
                    _address(reservation),
                    _netsh_client_id(target),
                    str(target.name),
                    self.owner,
                    "BOTH",
                ],
                "Ignore": False,
            },
        ]
        overridden = self._overridden_ids(reservation.conditions.values())
        codes = {int(code): code for code, _ in plain_items(options)}
        for option_id, value in _option_ids(options):
            if option_id in overridden:
                # Served by a policy instead; on the reservation it would win.
                continue
            commands.append(
                {
                    "Args": base
                    + [
                        "set",
                        "reservedoptionvalue",
                        _address(reservation),
                        str(option_id),
                        _netsh_type(codes[option_id]),
                    ]
                    # Each value is its own argument: that is how netsh takes a
                    # multi-valued option (two name servers, say).
                    + [str(item) for item in _values(value)],
                    "Ignore": False,
                }
            )
        # What was sent, not what the lease holds: an overridden option is
        # served by a policy and was never set on the reservation.
        verify = [
            {"Id": str(option_id), "Count": len(_values(value))}
            for option_id, value in _option_ids(options)
            if option_id not in overridden
        ]
        extra_commands, extra_lines = _split_extras(self.extras(reservation, "add"))
        # A netsh command from `extras()` runs after the reservation and its
        # options, which is the order a conditional needs: the thing it
        # overrides has to exist first.
        commands.extend(extra_commands)
        body = list(_NETSH_BODY)
        body.extend(extra_lines)
        # Verification runs last, after any extra command, so a conditional that
        # replaces an option is not reported as the option going missing.
        body.extend(_NETSH_VERIFY)
        payload = {
            "Commands": commands,
            "IPAddress": _address(reservation),
            "Verify": verify,
            "VerifyArgs": base + ["dump"],
        }
        return self.run(payload, body)

    def _keep_netsh(
        self,
        reservation: Reservation,
        options: DHCPOptions,
        applied: Dict[int, Any],
        wanted: Dict[int, Any],
    ) -> str:
        """`keep` through netsh: set the wanted options, delete the rest."""
        address = _address(reservation)
        base = self._netsh_scope(_scope(reservation))
        codes = {int(code): code for code, _ in plain_items(options)}
        commands = [
            {
                "Args": base
                + ["set", "reservedoptionvalue", address, str(option_id)]
                + [_netsh_type(codes[option_id])]
                + [str(item) for item in _values(value)],
                "Ignore": False,
            }
            for option_id, value in wanted.items()
        ]
        commands += [
            # Already absent is success: completion re-runs.
            {
                "Args": base
                + ["delete", "reservedoptionvalue", address, str(option_id)],
                "Ignore": True,
            }
            for option_id in applied
            if option_id not in wanted
        ]
        extra_commands, extra_lines = _split_extras(self.extras(reservation, "remove"))
        commands.extend(extra_commands)
        body = list(_NETSH_BODY) + extra_lines + list(_NETSH_VERIFY)
        payload = {
            "Commands": commands,
            "IPAddress": address,
            "Verify": [
                {"Id": str(option_id), "Count": len(_values(value))}
                for option_id, value in wanted.items()
            ],
            "VerifyArgs": base + ["dump"],
        }
        return self.run(payload, body)

    def _remove_netsh(self, reservation: Reservation) -> str:
        target = reservation.target
        base = self._netsh_scope(_scope(reservation))
        commands = [
            {
                # Deleting a reservation that is not there is success here, the
                # same as in the PowerShell path: cleanup re-runs.
                "Args": base
                + [
                    "delete",
                    "reservedip",
                    _address(reservation),
                    _netsh_client_id(target),
                ],
                "Ignore": True,
            }
        ]
        extra_commands, extra_lines = _split_extras(self.extras(reservation, "remove"))
        commands.extend(extra_commands)
        body = list(_NETSH_BODY)
        body.extend(extra_lines)
        return self.run({"Commands": commands}, body)

    # -- running PowerShell ------------------------------------------------

    def _recording(self, sent: List[str]) -> Any:
        """Each script the shell would be given, payload included."""

        def run(payload: Dict[str, Any], body: List[str]) -> str:
            sent.append(self.script_for(payload, body))
            return _FINISHED

        return self._replaced(run=run)

    def script_for(self, payload: Dict[str, Any], body: List[str]) -> str:
        """The script we will run: parameters as data, never as source."""
        # json.dumps escapes every non-ASCII character, typographic quotes
        # included, so doubling the ASCII quote is all the literal needs.
        encoded = _json.dumps(payload).replace("'", "''")
        return _SCRIPT.format(payload=encoded, body="\n".join(body))

    def host_config(self) -> Any:
        """The hostctl config of the shell this server's scripts run in."""
        import hostctl
        from hostctl.shell import POWERSHELL

        if self.transport == "local":
            return hostctl.LocalConfig(timeout=self.timeout)
        password = self.secret("password") or None
        if self.transport == "ssh":
            # A Windows OpenSSH server hands the command to cmd.exe, which a
            # Windows path flavour tells hostctl.
            return hostctl.SSHConfig(
                self.hostname,
                port=self.port or 22,
                username=self.user or None,
                password=password,
                shell=POWERSHELL,
                pathname="windows",
                timeout=self.timeout,
            )
        return hostctl.WinRMConfig(
            self.hostname,
            username=self.user,
            password=password,
            auth=self.auth,
            port=self.port,
            tls=self.ssl,
            timeout=self.timeout,
        )

    def run(self, payload: Dict[str, Any], body: List[str]) -> str:
        """Run `body` on the transport, with `payload` as `$p`; its output.

        :raises ServerError: the script failed, ended without reaching its
            last line, or the shell could not be reached.
        :raises BackendUnavailableError: the transport's extra is missing.
        """
        script = self.script_for(payload, body)
        LOGGER.debug("windhcp %s: %s", self.transport, self)
        try:
            with _open_host(self.host_config()) as host:
                done = host.run(script, check=False, text=True)
        except ImportError as exc:
            extra = getattr(exc, "extra", None) or self.transport
            raise BackendUnavailableError(
                f"the Windows DHCP backend over {self.transport} requires the "
                f"{extra!r} extra: pip install pydhcpctl[{extra}]"
            ) from exc
        except _subprocess.TimeoutExpired as exc:
            raise ServerError(
                f"windhcp: the PowerShell script on {self} did not finish in "
                f"{self.timeout:g} seconds"
            ) from exc
        except OSError as exc:
            raise ServerError(f"windhcp: cannot reach {self}: {exc}") from exc
        output = done.stdout or ""
        if done.returncode != 0:
            raise ServerError(
                f"windhcp: PowerShell on {self} failed ({done.returncode}): "
                f"{(done.stderr or output).strip()}"
            )
        if not _FINISHED.search(output):
            raise ServerError(
                f"windhcp: the {self.transport} PowerShell script ended without "
                f"finishing: {output.strip() or 'no output'}"
            )
        return output


def _open_host(config: Any) -> Any:
    """An open hostctl host for `config`, closed by `with`."""
    return config.open()


#: `match` key -> the `-Type` of the Windows DHCP class that carries it.
_CLASS_TYPES = {"user-class": "User", "vendor-class": "Vendor"}


def _classes_for(condition: Condition) -> List[Dict[str, str]]:
    """The user/vendor classes this condition's policy needs to exist.

    The class is named after the value the client sends, which is also its data:
    an `iPXE` user class named `iPXE` is what an administrator would have created
    by hand, and matching that means the backend reuses theirs instead of inventing a
    parallel name.
    """
    return [
        {"Name": str(value), "Type": _CLASS_TYPES[key], "Data": str(value)}
        for key, value in condition.match.items()
        if key in _CLASS_TYPES
    ]


def _split_extras(extras: List[Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Sort `extras()` output into netsh commands and PowerShell lines.

    A mapping is a netsh command (`{"Args": [...], "Ignore": False}`), its
    arguments a list. Anything else is a PowerShell line, which is valid under either method --
    netsh mode is still PowerShell, it just calls netsh.
    """
    commands: List[Dict[str, Any]] = []
    lines: List[str] = []
    for extra in extras:
        if isinstance(extra, dict):
            args = extra.get("Args", [])
            if isinstance(args, (str, bytes)):
                raise ConfigError(
                    f"a netsh command's Args is a list of arguments, not {args!r}"
                )
            commands.append(
                {
                    "Args": [str(a) for a in args],
                    "Ignore": bool(extra.get("Ignore")),
                }
            )
        else:
            lines.append(str(extra))
    return commands, lines


def _script_lines(extras: List[Any]) -> List[str]:
    """`extras()` output as PowerShell lines, for the cmdlet method.

    A netsh command reaching the cmdlet path is turned into the `netsh` call it
    describes rather than dropped: an override that knows netsh is still usable
    when the method is `powershell`, and silently ignoring it would be worse.
    """
    lines: List[str] = []
    commands, plain = _split_extras(extras)
    for command in commands:
        rendered = " ".join(_ps_quote(arg) for arg in command["Args"])
        if command["Ignore"]:
            lines.append(f"& netsh {rendered} 2>&1 | Out-Null")
        else:
            lines.append(f"$out = & netsh {rendered} 2>&1 | Out-String")
            lines.append(
                'if ($LASTEXITCODE -ne 0) { throw "netsh failed '
                '($LASTEXITCODE): $out" }'
            )
    lines.extend(plain)
    return lines


#: What closes a PowerShell single-quoted string: the ASCII quote and the four
#: typographic single quotes, each escaped by doubling it.
_PS_QUOTES = "'\u2018\u2019\u201a\u201b"


def _ps_quote(value: Any) -> str:
    """A PowerShell single-quoted literal of `value`, whatever it holds."""
    text = str(value)
    for quote in _PS_QUOTES:
        text = text.replace(quote, quote * 2)
    return "'" + text + "'"


def _scope(reservation: Reservation) -> str:
    """The Windows scope id: declared on the scope, else its network address."""
    scope = reservation.scope
    if scope.scope_id:
        return str(scope.scope_id)
    if scope.network is None:
        raise ConfigError(
            f"windhcp: scope {scope.name!r} has neither a network nor a "
            "scope_id, and a Windows scope is identified by its network address"
        )
    return str(scope.network.network_address)


def _require_mac(target: Target) -> MACAddress:
    """The client's MAC, or a clear error: a reservation is identified by one."""
    return target.require_mac("a Windows DHCP reservation is identified by one")


def _address(reservation: Reservation) -> str:
    """A Windows reservation is an address: the client's, or a clear error."""
    return str(reservation.require_ip("a Windows DHCP reservation is an address"))


def _client_id(target: Target) -> str:
    """Windows identifies a reservation by MAC, in its hyphen spelling."""
    return _require_mac(target).format("-")


def _netsh_client_id(target: Target) -> str:
    """netsh wants the MAC as bare hex; the cmdlets want it hyphenated."""
    return _require_mac(target).hex()


def _values(value: Any) -> List[Any]:
    """A value as the list netsh takes, one argument per entry.

    A flag is the BYTE Windows stores for it, 1 or 0: `True` is no byte.
    """
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, bool):
        return [int(value)]
    return [value]


def _served(lease: DHCPLease) -> DHCPOptions:
    """What Windows serves for `lease`, all of it options.

    A Windows reservation has no BOOTP header fields of its own, so the boot
    file is option 67 and the server name option 66, unless the lease sets
    those options itself; `siaddr` has no Windows equivalent.
    """
    options = lease.options.copy()
    for code, value in (
        (DHCPOptionCode.BOOTFILE_NAME, lease.file),
        (DHCPOptionCode.TFTP_SERVER, lease.sname),
    ):
        if value and code not in options:
            options[code] = value
    return options


def _warn_dropped(lease: DHCPLease) -> None:
    """Say what a Windows reservation is not given, rather than drop it silently."""
    dropped = [f"option {int(code)}" for code in lease.options if code in _SKIPPED]
    if not lease.siaddr.is_unspecified:
        dropped.append(f"next-server {lease.siaddr}")
    if dropped:
        LOGGER.warning(
            "windhcp: a Windows reservation cannot carry %s; it is not sent",
            ", ".join(dropped),
        )


def _option_ids(options: DHCPOptions) -> List[Tuple[int, Any]]:
    """Options as (option id, value) pairs: the id is the code.

    The value is **unformatted**: the cmdlets take a multi-valued option as one
    comma-joined string (`_value`), netsh as one argument per value (`_values`),
    and joining it here would have made the second impossible.
    """
    return [
        (int(code), _unsigned(value))
        for code, value in plain_items(options)
        if code not in _SKIPPED
    ]


def _unsigned(value: Any) -> Any:
    """A negative number as the DWORD Windows stores: it refuses `-3600` for
    option 2 (WIN32 87) and takes its two's complement."""
    if isinstance(value, int) and not isinstance(value, bool) and value < 0:
        return value % 2**32
    return value
