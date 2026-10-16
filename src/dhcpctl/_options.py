"""DHCP options: one vocabulary, each backend translates.

A backend is configured by a URI. Its **query string** carries two kinds of key:

* a **connection setting** the backend declares in its own ``SETTINGS``
  (where the server is, how to reach it, which files to write);
* everything else is a **client option** -- what the server tells the client.

A third kind is refused there: anything that varies per client or per scope
(`APPLY_TIME`). A boot file pinned to a connection would hand every client on
that server the same one, invisibly.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from .exceptions import ConfigError

__all__ = [
    "GENERIC_OPTIONS",
    "APPLY_TIME",
    "OPTIONS_BUILDER",
    "RAW_PREFIX",
    "PHASES",
    "DHCPOptions",
    "is_option",
    "split_query",
]

#: Option names every backend translates. A numeric `option-<n>` (or a bare
#: number) is always accepted too, for anything not modelled here.
GENERIC_OPTIONS = frozenset(
    {
        "router",
        "domain-name-servers",
        "domain-name",
        "domain-search",
        "next-server",
        "boot-file-name",
        "tftp-server-name",
        "host-name",
        "subnet-mask",
        "broadcast-address",
        "lease-time",
        "ntp-servers",
        "vendor-class-identifier",
    }
)

#: Keys that depend on the client or its scope and so are refused in a
#: connection URI. The value says where they belong instead.
APPLY_TIME = {
    "subnet_id": "the reservation's scope (Scope.subnet_id)",
    "scope": "the reservation's scope (Scope.scope_id)",
    "boot-file-name": "the reservation's options",
    "next-server": "the reservation's options",
    "tftp-server-name": "the reservation's options",
    "host-name": "the reservation's target (Target.hostname)",
}

#: Query key naming a callable the *caller* applies to the options it builds;
#: dhcpctl stores it as `DHCPServer.options_builder` and does not call it.
OPTIONS_BUILDER = "options_builder"

#: Query-key prefix for backend-native text that is never translated:
#: ``raw.dnsmasq=...``. A phase may be appended (``raw.dhcpd.remove=...``);
#: a bare ``raw.<backend>`` is ``add``.
RAW_PREFIX = "raw."

#: The phases a raw fragment, or `DHCPServer.extras`, belongs to.
PHASES = ("add", "remove")

_RAW_PHASE_SEP = "."


def is_option(name: str) -> bool:
    """Is `name` a client option some backend can carry?"""
    if name in GENERIC_OPTIONS:
        return True
    if name.startswith("option-"):
        return name[len("option-") :].isdigit()
    return name.isdigit()


class DHCPOptions(dict):
    """Client options, generic name -> value, plus untranslated per-backend text.

    `raw` maps a backend name, optionally suffixed `.remove`, to the lines
    that backend emits verbatim.
    """

    def __init__(
        self,
        *args: Any,
        raw: "Optional[Dict[str, Iterable[Any]]]" = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.raw: Dict[str, List[Any]] = {k: list(v) for k, v in (raw or {}).items()}

    def raw_for(self, backend: str, phase: str = "add") -> List[Any]:
        """The untranslated lines `backend` emits for `phase` (`add` or `remove`).

        A key with no phase (`raw.dhcpd=`) belongs to `add`.
        """
        lines = list(self.raw.get(f"{backend}{_RAW_PHASE_SEP}{phase}", ()))
        if phase == "add":
            lines = list(self.raw.get(backend, ())) + lines
        return lines

    def copy(self) -> "DHCPOptions":
        return DHCPOptions(self, raw=self.raw)


def split_query(
    uri: str, settings: "Iterable[str]", backend: str
) -> "Tuple[Dict[str, str], DHCPOptions, Optional[str]]":
    """Split a backend URI's query into (settings, options, options builder).

    `settings` is the backend's own `SETTINGS`. Every other key is a client
    option, a `raw.<backend>` fragment or `options_builder`. A repeated key
    becomes a list, which is how a multi-valued option is written.

    :raises ConfigError: an unknown key, or one that belongs to the reservation.
    """
    known = set(settings)
    found_settings: Dict[str, str] = {}
    options = DHCPOptions()
    builder: Optional[str] = None

    for key, value in parse_qsl(urlsplit(uri).query, keep_blank_values=True):
        if key in known:
            found_settings[key] = value
        elif key == OPTIONS_BUILDER:
            builder = value
        elif key.startswith(RAW_PREFIX):
            name = key[len(RAW_PREFIX) :]
            backend_name, _, phase = name.rpartition(_RAW_PHASE_SEP)
            if backend_name and phase in PHASES:
                name = f"{backend_name}{_RAW_PHASE_SEP}{phase}"
            options.raw.setdefault(name, []).append(value)
        elif key in APPLY_TIME:
            raise ConfigError(
                f"{key!r} cannot be set on a {backend} connection: it depends on "
                f"the client being reserved. Put it in {APPLY_TIME[key]}."
            )
        elif is_option(key):
            _add(options, key, value)
        else:
            raise ConfigError(
                f"unknown key {key!r} in a {backend} connection: it is neither a "
                f"{backend} setting ({', '.join(sorted(known)) or 'none'}) nor a "
                f"DHCP option ({', '.join(sorted(GENERIC_OPTIONS))}, option-<n>)"
            )
    return found_settings, options, builder


def _add(options: DHCPOptions, key: str, value: Any) -> None:
    """Set or extend `key`; a repeated key is a multi-valued option."""
    if key not in options:
        options[key] = value
        return
    current = options[key]
    if not isinstance(current, list):
        current = [current]
    current.append(value)
    options[key] = current
