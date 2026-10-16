"""One interface to DHCP servers: arm a reservation, then remove or keep it.

```python
import dhcpctl

server = dhcpctl.connect("kea://kea01:8000/?service=dhcp4")
target = dhcpctl.Target("web01", mac=MACAddress("aa:bb:cc:dd:ee:ff"), ip=...)
server.add(dhcpctl.Reservation(target, scope, server.client_options({...})))
```

Backends are chosen by URI scheme (`dnsmasq`, `kea`/`keas`, `dhcpd`,
`windhcp`, or one registered with `register_backend` or the `dhcpctl.backends`
entry-point group). Importing dhcpctl imports no backend and no optional
dependency.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from . import exceptions
from ._completion import BOOT_OPTIONS, Completion, parse_completion
from ._conditions import MATCH_KEYS, NAME_CHARS, Condition, parse_conditions
from ._model import NULL_MAC, Reservation, Scope, Target
from ._options import (
    APPLY_TIME,
    GENERIC_OPTIONS,
    OPTIONS_BUILDER,
    PHASES,
    RAW_PREFIX,
    DHCPOptions,
    is_option,
)
from ._registry import (
    ENTRY_POINT_GROUP,
    backend_names,
    connect,
    get_backend,
    register_backend,
    unregister_backend,
)
from ._server import DEFAULT_OWNER, DHCPServer, Secrets
from .exceptions import (
    BackendUnavailableError,
    ConditionMissingError,
    ConditionUnsupportedError,
    ConfigError,
    DHCPCtlError,
    MissingMACError,
    ReservationExistsError,
    ServerError,
    UnknownBackendError,
)

try:
    __version__ = version("dhcpctl")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0"

__all__ = [
    "__version__",
    # connecting
    "connect",
    "register_backend",
    "unregister_backend",
    "backend_names",
    "get_backend",
    "ENTRY_POINT_GROUP",
    "DEFAULT_OWNER",
    "Secrets",
    # the contract
    "DHCPServer",
    "Reservation",
    "Target",
    "Scope",
    "NULL_MAC",
    # options
    "DHCPOptions",
    "GENERIC_OPTIONS",
    "APPLY_TIME",
    "OPTIONS_BUILDER",
    "RAW_PREFIX",
    "PHASES",
    "is_option",
    # conditions and completion
    "Condition",
    "MATCH_KEYS",
    "NAME_CHARS",
    "parse_conditions",
    "Completion",
    "BOOT_OPTIONS",
    "parse_completion",
    # errors
    "exceptions",
    "DHCPCtlError",
    "ConfigError",
    "UnknownBackendError",
    "BackendUnavailableError",
    "MissingMACError",
    "ServerError",
    "ReservationExistsError",
    "ConditionUnsupportedError",
    "ConditionMissingError",
]
