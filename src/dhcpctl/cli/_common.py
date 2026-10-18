"""What the commands share: the server, and the reservation they act on."""

from __future__ import annotations

import json
import os
import sys
import typing as _ty

from duho import Cmd, LoggingArgs, UsageError

from .._model import Reservation, Scope, Target
from .._registry import connect
from .._server import DHCPServer

__all__ = ["Command", "ReservationCommand", "parse_option"]

#: The secrets a shipped backend asks for; each is read from `DHCPCTL_<NAME>`.
SECRETS = ("user", "password", "keyname", "omapi_key")


class Command(LoggingArgs, Cmd):
    """Options every server command takes: the server's URI and the owner."""

    _logger_name_ = "dhcpctl"

    uri: str
    "The server as a URI; its scheme picks the backend (dnsmasq, kea, dhcpd, windhcp)"
    ("uri",)

    owner: str = "dhcpctl"
    "The name written on what is armed, which marks it as this tool's"
    ("--owner",)

    def server(self) -> DHCPServer:
        """The backend for `uri`, with each `DHCPCTL_<SECRET>` the environment sets.

        A secret is never a field: an argument is visible to every process.
        """
        secrets = {
            name: os.environ[f"DHCPCTL_{name.upper()}"]
            for name in SECRETS
            if os.environ.get(f"DHCPCTL_{name.upper()}")
        }
        return connect(self.uri, secrets=secrets, owner=self.owner)


class ReservationCommand(Command):
    """A command on one client's reservation: from flags, or from a document."""

    name: _ty.Optional[str] = None
    "The client's name on the server (dhcpd host, Windows reservation, dnsmasq tag)"
    ("--name", "-n")

    mac: _ty.Optional[str] = None
    "The client's MAC, which every backend keys a reservation by"
    ("--mac", "-m")

    ip: _ty.Optional[str] = None
    "The address reserved for it; omitted, the reservation is the MAC alone"
    ("--ip",)

    hostname: _ty.Optional[str] = None
    "The client's host name, where the backend writes one"
    ("--hostname",)

    network: _ty.Optional[str] = None
    "The scope's network (10.0.0.0/24): a Windows scope, a Kea subnet"
    ("--network",)

    subnet_id: _ty.Optional[int] = None
    "Kea's subnet id, over what --network finds"
    ("--subnet-id",)

    scope_id: _ty.Optional[str] = None
    "The Windows scope id, over what --network gives"
    ("--scope-id",)

    options: _ty.List[str] = []
    "An option or header field served, name=value; a comma makes a list, json: a JSON value; repeat for more"
    ("--option", "-o")

    source: _ty.Optional[str] = None
    "A reservation document (.json, .yaml, .toml, .ini, or - for JSON on standard input), instead of the flags"
    ("--from",)

    def reservation(self, server: DHCPServer) -> Reservation:
        """The reservation the flags or `--from` describe, read with `server.codes`."""
        if self.source is not None:
            given = [
                flag for flag in ("name", "mac", "ip", "network") if getattr(self, flag)
            ]
            if given or self.options:
                raise UsageError(
                    "--from describes the whole reservation; give no other flag"
                )
            return _read(self.source, server)
        if not self.name:
            raise UsageError(
                "give the client's --name, or a reservation --from a document"
            )
        from netimps import IPNetwork, MACAddress, parse

        lease = server.codes.lease(
            dict(parse_option(option) for option in self.options), "--option"
        )
        if self.ip:
            lease = lease.replace(ip=self.ip)
        return Reservation(
            target=Target(
                self.name,
                mac=parse(self.mac, MACAddress) if self.mac else None,
                hostname=self.hostname or "",
            ),
            scope=Scope(
                network=parse(self.network, IPNetwork) if self.network else None,
                subnet_id=self.subnet_id,
                scope_id=self.scope_id,
            ),
            lease=lease,
        )


def parse_option(text: str) -> "tuple[str, _ty.Any]":
    """`name=value` as `(name, value)`: `json:` reads JSON, a comma makes a list."""
    name, sep, value = text.partition("=")
    if not sep or not name:
        raise UsageError(f"--option {text!r}: expected name=value")
    if value.startswith("json:"):
        try:
            return name, json.loads(value[5:])
        except ValueError as exc:
            raise UsageError(f"--option {name}: not JSON: {exc}") from exc
    if "," in value:
        return name, [item.strip() for item in value.split(",")]
    return name, value


#: A document's format, by its suffix.
_FORMATS = {
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".ini": "ini",
}


def _read(source: str, server: DHCPServer) -> Reservation:
    if source == "-":
        return Reservation.from_text(sys.stdin.read(), "json", codes=server.codes)
    suffix = os.path.splitext(source)[1].lower()
    if suffix not in _FORMATS:
        raise UsageError(
            f"--from {source}: name it .json, .yaml, .toml or .ini, or give - for JSON"
        )
    with open(source, encoding="utf-8") as handle:
        return Reservation.from_text(
            handle.read(), _FORMATS[suffix], codes=server.codes
        )
