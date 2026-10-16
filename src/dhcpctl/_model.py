"""What a reservation is made of: the client, its scope, and what to serve it."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from netimps import IPAddress, IPNetwork, MACAddress

from ._completion import Completion
from ._conditions import Condition
from ._options import DHCPOptions
from .exceptions import MissingMACError

__all__ = ["Target", "Scope", "Reservation", "NULL_MAC"]

#: The all-zero MAC some configurations use for "no MAC known"; treated as none.
NULL_MAC = "00:00:00:00:00:00"


@dataclass(frozen=True)
class Target:
    """The client a reservation is for.

    `name` labels it on the server (the dhcpd host name, the Windows reservation
    name, the dnsmasq tag) and in messages.
    """

    name: str
    mac: Optional[MACAddress] = None
    ip: Optional[IPAddress] = None
    hostname: str = ""

    @property
    def ip_text(self) -> str:
        """The address as text, or `""` when there is none."""
        return str(self.ip) if self.ip else ""

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


@dataclass(frozen=True)
class Reservation:
    """One client's reservation, as a backend applies it.

    `options` are the fully merged client options; `conditions` the named
    conditions that apply to it; `completion` what happens when it completes;
    `extras` per-phase backend-native fragments added to the server's own;
    `context` is the caller's, carried untouched for a backend subclass that
    decides fragments per client.
    """

    target: Target
    scope: Scope = field(default_factory=Scope)
    options: DHCPOptions = field(default_factory=DHCPOptions)
    conditions: Mapping[str, Condition] = field(default_factory=dict)
    completion: Completion = field(default_factory=Completion)
    extras: Mapping[str, Sequence[Any]] = field(default_factory=dict)
    context: Any = None
