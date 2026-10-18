"""Shared fixtures.

Every backend test needs the same thing: a `Reservation` for one client, built
the way a caller builds it -- options already merged, conditions and completion
already parsed. `reservation` is that factory. The registry is restored after
every test, so a backend one test registers cannot answer another's scheme.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Mapping, Optional

import pytest
from netimps import MACAddress

import dhcpctl
from dhcpctl import _registry

#: The client most tests reserve.
MAC = "aa:bb:cc:dd:ee:ff"

#: The iPXE chainload, declared once: a PXE ROM is handed `undionly.kpxe` and
#: iPXE itself `boot.ipxe`, or it loads itself forever.
IPXE = {
    "ipxe": {
        "match": {"user-class": "iPXE"},
        "options": {"file": "boot.ipxe"},
    }
}


@pytest.fixture(autouse=True)
def isolate_registry():
    """Put the scheme registry back as it was, entry-point state included."""
    saved = dict(_registry._REGISTRY)
    loaded = _registry._ENTRY_POINTS_LOADED
    yield
    _registry._REGISTRY.clear()
    _registry._REGISTRY.update(saved)
    _registry._ENTRY_POINTS_LOADED = loaded


@pytest.fixture
def reservation():
    """Build a `Reservation` for `web01` (10.0.0.10, aa:bb:cc:dd:ee:ff) in 10.0.0.0/24.

    The lease is layered as a caller would: `defaults` (what a scope implies,
    say a router), then `options`, later winning; `options` may hold header
    fields (`file`, `next-server`), and `next_server` sets `siaddr`. Names,
    here and in `conditions` and `completion`, are read with the server's
    codemap (`server.codes`), or pydhcp's without one.
    `mac=None` and `ip=None` build a client without one.
    """

    def build(
        server: Optional[dhcpctl.DHCPServer] = None,
        options: Optional[Mapping[str, Any]] = None,
        *,
        defaults: Optional[Mapping[str, Any]] = None,
        next_server: Optional[str] = None,
        name: str = "web01",
        mac: Optional[str] = MAC,
        ip: Optional[str] = "10.0.0.10",
        hostname: str = "web01",
        network: Optional[str] = "10.0.0.0/24",
        scope_name: str = "lan",
        subnet_id: Optional[int] = None,
        scope_id: Optional[str] = None,
        conditions: Any = None,
        completion: Any = None,
        extras: Optional[Mapping[str, Any]] = None,
        context: Any = None,
    ) -> dhcpctl.Reservation:
        codes = server.codes if server is not None else dhcpctl.PYDHCP_CODES
        lease = codes.lease(options)
        lease = lease.replace(
            ip=ip or "0.0.0.0",
            options=codes.options(defaults).copy(lease.options),
            siaddr=next_server or lease.siaddr,
            strict=False,
        )
        if isinstance(conditions, dict) and not all(
            isinstance(c, dhcpctl.Condition) for c in conditions.values()
        ):
            conditions = dhcpctl.parse_conditions(conditions, "test", codes)
        if isinstance(completion, dict):
            completion = dhcpctl.parse_completion(completion, "test", codes)
        target = dhcpctl.Target(
            name,
            mac=MACAddress(mac) if mac is not None else None,
            hostname=hostname,
        )
        scope = dhcpctl.Scope(
            scope_name,
            network=ipaddress.ip_network(network) if network is not None else None,
            subnet_id=subnet_id,
            scope_id=scope_id,
        )
        return dhcpctl.Reservation(
            target,
            scope,
            lease,
            conditions=conditions or {},
            completion=completion or dhcpctl.Completion(),
            extras=extras or {},
            context=context,
        )

    return build


@pytest.fixture
def ipxe():
    """The `ipxe` condition, parsed."""
    return dhcpctl.parse_conditions(IPXE, "test")["ipxe"]
