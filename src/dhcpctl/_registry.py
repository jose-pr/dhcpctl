"""Which backend serves which URI scheme."""

from __future__ import annotations

import importlib
import logging
from typing import Dict, Tuple, Type, Union
from urllib.parse import urlsplit

from ._server import DEFAULT_OWNER, DHCPServer, Secrets
from .exceptions import ConfigError, UnknownBackendError

__all__ = [
    "ENTRY_POINT_GROUP",
    "register_backend",
    "unregister_backend",
    "backend_names",
    "get_backend",
    "connect",
]

LOGGER = logging.getLogger("dhcpctl")

#: Entry-point group an installed package registers a backend under; the entry
#: point's name is the scheme.
ENTRY_POINT_GROUP = "dhcpctl.backends"

#: Shipped backends, imported only when their scheme is first used.
_SHIPPED: Dict[str, str] = {
    "dnsmasq": "dhcpctl.backends._dnsmasq:DnsmasqBackend",
    "kea": "dhcpctl.backends._kea:KeaBackend",
    "keas": "dhcpctl.backends._kea:KeaBackend",
    "dhcpd": "dhcpctl.backends._dhcpd:DHCPDBackend",
    "windhcp": "dhcpctl.backends._windhcp:WinDHCPBackend",
}

_REGISTRY: Dict[str, Union[str, Type[DHCPServer]]] = dict(_SHIPPED)
_ENTRY_POINTS_LOADED = False


def register_backend(
    scheme: str, backend: Union[str, Type[DHCPServer]], *, replace: bool = False
) -> None:
    """Serve `scheme` with `backend` (a class, or `"module:Class"` to import lazily).

    :raises ValueError: `scheme` is already served by another backend and
        `replace` is false.
    """
    scheme = scheme.lower()
    current = _REGISTRY.get(scheme)
    if current is not None and current != backend and not replace:
        raise ValueError(
            f"scheme {scheme!r} is already served by {_label(current)}; pass "
            f"replace=True to serve it with {_label(backend)} instead"
        )
    _REGISTRY[scheme] = backend


def unregister_backend(scheme: str) -> bool:
    """Stop serving `scheme`; True if it was registered."""
    return _REGISTRY.pop(scheme.lower(), None) is not None


def backend_names() -> Tuple[str, ...]:
    """Every registered scheme, sorted."""
    _load_entry_points()
    return tuple(sorted(_REGISTRY))


def get_backend(scheme: str) -> Type[DHCPServer]:
    """The backend class serving `scheme`, imported if it was registered by name.

    :raises UnknownBackendError: no backend serves `scheme`.
    """
    scheme = scheme.lower()
    backend = _REGISTRY.get(scheme)
    if backend is None:
        _load_entry_points()
        backend = _REGISTRY.get(scheme)
    if backend is None:
        raise UnknownBackendError(
            f"no dhcpctl backend serves scheme {scheme!r}; registered: "
            f"{', '.join(sorted(_REGISTRY)) or 'none'}. Register one with "
            f"dhcpctl.register_backend or the {ENTRY_POINT_GROUP!r} entry point"
        )
    if isinstance(backend, str):
        module, _, name = backend.partition(":")
        backend = getattr(importlib.import_module(module), name)
        _REGISTRY[scheme] = backend
    return backend


def connect(
    uri: str, *, secrets: Secrets = None, owner: str = DEFAULT_OWNER
) -> DHCPServer:
    """The backend for `uri`'s scheme, built from `uri`. Does no I/O.

    `secrets` supplies what the URI must not carry (see `DHCPServer.secret`);
    `owner` names the entries this server writes (see `DHCPServer.owner`).

    :raises UnknownBackendError: no backend serves the scheme.
    :raises ConfigError: the URI cannot be used by that backend.
    """
    scheme = urlsplit(uri).scheme
    if not scheme:
        raise ConfigError(f"{uri!r} has no scheme, so no backend can be chosen")
    return get_backend(scheme)(uri, secrets=secrets, owner=owner)


def _label(backend: Union[str, Type[DHCPServer]]) -> str:
    if isinstance(backend, str):
        return backend
    return f"{backend.__module__}:{backend.__qualname__}"


def _load_entry_points() -> None:
    """Register the backends installed packages declare, once per process."""
    global _ENTRY_POINTS_LOADED
    if _ENTRY_POINTS_LOADED:
        return
    _ENTRY_POINTS_LOADED = True
    from importlib.metadata import entry_points

    try:
        found = entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:  # pragma: no cover - Python 3.9 takes no keyword
        found = entry_points().get(ENTRY_POINT_GROUP, ())
    for entry in found:
        if entry.name.lower() not in _REGISTRY:
            _REGISTRY[entry.name.lower()] = entry.value
        else:
            LOGGER.warning(
                "entry point %r for scheme %r ignored: the scheme is already "
                "served by %s",
                entry.value,
                entry.name,
                _label(_REGISTRY[entry.name.lower()]),
            )
