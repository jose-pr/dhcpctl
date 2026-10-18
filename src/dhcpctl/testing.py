"""The contract every backend must pass, shipped so a third-party backend runs it too.

Subclass :class:`BackendContract` in a pytest module and set the class
attributes; pytest collects the inherited tests::

    from dhcpctl.testing import BackendContract

    class TestMyBackend(BackendContract):
        uri = "mine://server01/"
        secret_uri = "mine://admin:{secret}@server01/"

The suite talks to no server: what an operation would send is checked through
`DHCPServer.render`, so a backend passes it once it can render. Needs pytest. A
backend is not done until it passes this suite unmodified.
"""

from __future__ import annotations

import typing as _ty
from ipaddress import ip_network

import pytest
from netimps import MACAddress

from ._completion import Completion
from ._conditions import parse_conditions
from ._model import Reservation, Scope, Target
from ._registry import connect
from ._server import DHCPServer
from .exceptions import (
    ConditionUnsupportedError,
    ConfigError,
    MissingMACError,
)

__all__ = ["BackendContract", "SECRET"]

#: Planted where a URI carries a password; it must never be shown.
SECRET = "hunter2-dhcpctl-secret"

MAC = "aa:bb:cc:dd:ee:ff"


class BackendContract:
    """Behaviour every `DHCPServer` backend must have.

    Attributes to set:
        uri: A URI building the backend under test; building does no I/O.
        secret_uri: The same with `{secret}` where a password goes, or None
            when the backend's URI takes no password.
        keyed_by_mac: Whether the backend refuses a client with no MAC, with
            `MissingMACError`. Every shipped backend is.
    """

    uri: _ty.ClassVar[str]
    secret_uri: _ty.ClassVar[_ty.Optional[str]] = None
    keyed_by_mac: _ty.ClassVar[bool] = True

    def server(self) -> DHCPServer:
        return connect(self.uri)

    def reservation(self, server: DHCPServer, **changes: _ty.Any) -> Reservation:
        """`web01`, 10.0.0.10 in 10.0.0.0/24 (Kea subnet 1), with a router and a
        boot file; `changes` replace its fields (`mac=None` drops the MAC)."""
        mac = changes.pop("mac", MAC)
        lease = server.codes.lease({"router": "10.0.0.1", "file": "undionly.kpxe"})
        fields: _ty.Dict[str, _ty.Any] = {
            "target": Target("web01", mac=MACAddress(mac) if mac else None),
            "scope": Scope("lan", network=ip_network("10.0.0.0/24"), subnet_id=1),
            "lease": lease.replace(ip="10.0.0.10"),
        }
        fields.update(changes)
        return Reservation(**fields)

    def test_is_a_backend_built_from_its_uri(self) -> None:
        server = self.server()
        assert isinstance(server, DHCPServer)
        assert all(isinstance(name, str) for name in type(server).SETTINGS)

    def test_a_uri_carries_no_option(self) -> None:
        separator = "&" if "?" in self.uri else "?"
        with pytest.raises(ConfigError):
            connect(f"{self.uri}{separator}router=10.0.0.1")

    def test_a_password_in_the_uri_is_never_shown(self) -> None:
        if self.secret_uri is None:
            pytest.skip("the backend's URI takes no password")
        server = connect(self.secret_uri.format(secret=SECRET))
        for shown in (str(server), repr(server), server.redacted_uri):
            assert SECRET not in shown

    def test_arming_renders_what_names_the_client(self) -> None:
        server = self.server()
        text = server.render(self.reservation(server))
        assert text.strip()
        spellings = {MAC, MAC.replace(":", "-"), MAC.replace(":", ""), "web01"}
        assert any(spelling in text.lower() for spelling in spellings)

    def test_removing_renders_something(self) -> None:
        server = self.server()
        assert server.render(self.reservation(server), "remove").strip()

    def test_completing_without_keeping_is_removing(self) -> None:
        server = self.server()
        reservation = self.reservation(server, completion=Completion())
        assert server.render(reservation, "complete") == server.render(
            reservation, "remove"
        )

    def test_keeping_renders(self) -> None:
        server = self.server()
        kept = self.reservation(
            server,
            completion=Completion(True, {"file": "sanboot.ipxe"}, codes=server.codes),
        )
        assert server.render(kept, "complete").strip()

    def test_a_client_with_no_mac_is_refused_before_anything_is_sent(self) -> None:
        if not self.keyed_by_mac:
            pytest.skip("the backend does not key reservations by MAC")
        server = self.server()
        with pytest.raises(MissingMACError):
            server.render(self.reservation(server, mac=None))

    def test_a_condition_is_served_or_refused_by_name(self) -> None:
        server = self.server()
        conditions = parse_conditions(
            {
                "ipxe": {
                    "match": {"user-class": "iPXE"},
                    "options": {"file": "boot.ipxe"},
                }
            },
            "contract",
            server.codes,
        )
        reservation = self.reservation(server, conditions=conditions)
        try:
            text = server.render(reservation)
        except ConditionUnsupportedError as exc:
            assert "ipxe" in str(exc)
            return
        assert "boot.ipxe" in text
        assert isinstance(server.condition_recipe(reservation, conditions["ipxe"]), str)

    def test_an_unknown_action_or_phase_is_refused(self) -> None:
        server = self.server()
        reservation = self.reservation(server)
        with pytest.raises(ValueError):
            server.render(reservation, "nuke")
        with pytest.raises(ValueError):
            server.extras(reservation, "later")
