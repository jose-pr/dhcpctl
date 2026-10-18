"""What a reservation is made of: the client, its scope, and what to serve it."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence

import ipaddress

import netimps
from netimps import IPNetwork, MACAddress
from pydhcp.packet import structured

from ._completion import Completion, parse_completion
from ._conditions import Condition, parse_conditions
from ._options import PHASES, PYDHCP_CODES, UNSPECIFIED, DHCPLease, OptionCodes
from .exceptions import ConfigError, MissingMACError

__all__ = ["Target", "Scope", "Reservation", "NULL_MAC"]

#: The all-zero MAC some configurations use for "no MAC known"; treated as none.
NULL_MAC = "00:00:00:00:00:00"


@dataclass(frozen=True)
class Target:
    """The client a reservation is for.

    `name` labels it on the server (the dhcpd host name, the Windows reservation
    name, the dnsmasq tag) and in messages. Its address is the lease's.
    """

    name: str
    mac: Optional[MACAddress] = None
    hostname: str = ""

    def require_mac(self, what: str) -> MACAddress:
        """The MAC, or `MissingMACError` saying `what` is identified by one."""
        if self.mac is None or str(self.mac) in ("", NULL_MAC):
            raise MissingMACError(
                f"target {self.name!r} has no MAC address, and {what}"
            )
        return self.mac


@dataclass(frozen=True)
class Scope:
    """Where the reservation lives on the server.

    `network` identifies a Windows scope and a Kea subnet; `subnet_id` and
    `scope_id` override what is derived from it. `name` labels it in messages
    and keys per-scope caches.
    """

    name: str = ""
    network: Optional[IPNetwork] = None
    subnet_id: Optional[int] = None
    scope_id: Optional[str] = None


def _no_address() -> DHCPLease:
    return DHCPLease(UNSPECIFIED, strict=False)


@dataclass(frozen=True)
class Reservation:
    """One client's reservation, as a backend applies it.

    `lease` is what the server answers the client with: a pydhcp `DHCPLease`
    holding its address (`0.0.0.0` for a MAC-only reservation), the fully
    merged options, and the BOOTP header fields `siaddr` (the next server),
    `sname` and `file` (the boot file). `conditions` are the named conditions
    that apply to it; `completion` what happens when it completes; `extras`
    per-phase backend-native fragments the backend emits verbatim; `context`
    is the caller's, carried untouched for a backend subclass that decides
    fragments per client.
    """

    target: Target
    scope: Scope = field(default_factory=Scope)
    lease: DHCPLease = field(default_factory=_no_address)
    conditions: Mapping[str, Condition] = field(default_factory=dict)
    completion: Completion = field(default_factory=Completion)
    extras: Mapping[str, Sequence[Any]] = field(default_factory=dict)
    context: Any = None

    @property
    def ip_text(self) -> str:
        """The address as text, or `""` when there is none (`0.0.0.0`)."""
        return "" if self.lease.ip.is_unspecified else str(self.lease.ip)

    def require_ip(self, what: str) -> ipaddress.IPv4Address:
        """The address, or `ConfigError` saying `what` needs one."""
        if self.lease.ip.is_unspecified:
            raise ConfigError(
                f"target {self.target.name!r} has no ip address, and {what}"
            )
        return self.lease.ip

    def to_mapping(self) -> Dict[str, Any]:
        """The reservation as plain data, the form `from_mapping` reads.

        `target`, `scope`, `lease` (`DHCPLease.to_mapping`'s form), and
        `conditions`, `completion` and `extras` when there are any. An unset
        field is left out. `context` is the caller's and is not written.
        """
        mapping: Dict[str, Any] = {
            "target": _drop_unset(
                name=self.target.name,
                mac=str(self.target.mac) if self.target.mac is not None else None,
                hostname=self.target.hostname,
            )
        }
        scope = _drop_unset(
            name=self.scope.name,
            network=str(self.scope.network) if self.scope.network is not None else None,
            **{"subnet-id": self.scope.subnet_id, "scope-id": self.scope.scope_id},
        )
        if scope:
            mapping["scope"] = scope
        mapping["lease"] = self.lease.to_mapping()
        if self.conditions:
            mapping["conditions"] = {
                name: condition.to_mapping()
                for name, condition in self.conditions.items()
            }
        if self.completion.keep:
            mapping["completion"] = self.completion.to_mapping()
        if self.extras:
            mapping["extras"] = {
                phase: list(items) for phase, items in self.extras.items()
            }
        return mapping

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any],
        *,
        codes: "Optional[type[OptionCodes]]" = None,
    ) -> "Reservation":
        """A reservation from a mapping in the shape `to_mapping` writes.

        Only `target.name` is required. `lease` is read by
        `DHCPLease.from_mapping` with the `codes` codemap (pydhcp's), its
        address optional; `conditions` and `completion` as `parse_conditions`
        and `parse_completion` read them.

        :raises ConfigError: an unknown key, or a field that cannot be read.
        """
        codes = codes or PYDHCP_CODES
        _known(
            "reservation",
            data,
            ("target", "scope", "lease", "conditions", "completion", "extras"),
        )
        target = _known("target", data.get("target"), ("name", "mac", "hostname"))
        if not target.get("name"):
            raise ConfigError("reservation target needs a `name`")
        name = str(target["name"])
        scope = _known(
            "scope",
            data.get("scope") or {},
            ("name", "network", "subnet-id", "scope-id"),
        )
        try:
            mac = target.get("mac")
            network = scope.get("network")
            built_target = Target(
                name,
                mac=netimps.parse(mac, netimps.MACAddress) if mac else None,
                hostname=str(target.get("hostname") or ""),
            )
            built_scope = Scope(
                name=str(scope.get("name") or ""),
                network=netimps.parse(network, netimps.IPNetwork) if network else None,
                subnet_id=scope.get("subnet-id"),
                scope_id=scope.get("scope-id"),
            )
        except ValueError as exc:
            raise ConfigError(f"reservation {name!r}: {exc}") from exc
        where = f"reservation {name}"
        extras = _known("extras", data.get("extras") or {}, PHASES)
        for phase, items in extras.items():
            if not isinstance(items, list):
                raise ConfigError(
                    f"{where}: extras.{phase} must be a list, got {type(items).__name__}"
                )
        return cls(
            built_target,
            built_scope,
            codes.read_lease(data.get("lease"), where),
            conditions=parse_conditions(data.get("conditions"), where, codes),
            completion=parse_completion(data.get("completion"), where, codes)
            or Completion(),
            extras={phase: list(items) for phase, items in extras.items()},
        )

    def to_text(self, format: str) -> str:
        """`to_mapping` as a `"json"`, `"yaml"`, `"toml"` or `"ini"` document,
        written by `pydhcp.packet.structured.dumps`, with its errors."""
        return structured.dumps(self.to_mapping(), format)

    @classmethod
    def from_text(
        cls,
        text: str,
        format: str,
        *,
        codes: "Optional[type[OptionCodes]]" = None,
    ) -> "Reservation":
        """`pydhcp.packet.structured.loads` then `from_mapping`, with their errors."""
        return cls.from_mapping(structured.loads(text, format), codes=codes)


def _drop_unset(**fields: Any) -> Dict[str, Any]:
    """The fields that hold something: no `None`, no empty text."""
    return {key: value for key, value in fields.items() if value not in (None, "")}


def _known(what: str, data: Any, keys: "Optional[Sequence[str]]") -> Dict[str, Any]:
    """`data` as a dict, refusing a non-mapping and, when `keys` is given, other keys."""
    if not isinstance(data, Mapping):
        raise ConfigError(f"{what} must be a mapping, got {type(data).__name__}")
    unknown = set(data) - set(keys) if keys is not None else set()
    if unknown:
        raise ConfigError(
            f"{what} has unknown key(s) {', '.join(sorted(map(str, unknown)))}; "
            f"it takes {', '.join(keys or ())}"
        )
    return dict(data)
