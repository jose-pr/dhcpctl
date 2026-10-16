"""The shipped backends, each imported only when first named.

`dhcpctl.connect(uri)` is the usual way to get one; these names are for
subclassing a backend or checking what `connect` returned.
"""

from __future__ import annotations

import importlib
from typing import Any

__all__ = ["DnsmasqBackend", "KeaBackend", "DHCPDBackend", "WinDHCPBackend"]

_MODULES = {
    "DnsmasqBackend": "_dnsmasq",
    "KeaBackend": "_kea",
    "DHCPDBackend": "_dhcpd",
    "WinDHCPBackend": "_windhcp",
}


def __getattr__(name: str) -> Any:
    module = _MODULES.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(f"{__name__}.{module}"), name)


def __dir__() -> "list[str]":
    return sorted(set(globals()) | set(__all__))
