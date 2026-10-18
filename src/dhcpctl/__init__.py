"""One interface to DHCP servers: arm a reservation, then remove or keep it.

```python
import dhcpctl

server = dhcpctl.connect("kea://kea01:8000/?service=dhcp4")
target = dhcpctl.Target("web01", mac=MACAddress("aa:bb:cc:dd:ee:ff"))
lease = server.codes.lease({"router": "10.0.0.1", "file": "undionly.kpxe"})
server.add(dhcpctl.Reservation(target, scope, lease.replace(ip="10.0.0.10")))
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
    BOOT_FIELDS,
    PHASES,
    PYDHCP_CODES,
    DHCPLease,
    DHCPOptionCode,
    DHCPOptions,
    OptionCodes,
    option_codes,
    plain_items,
    UNSPECIFIED,
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
    ServerError,
    UnknownBackendError,
)

try:
    __version__ = version("pydhcpctl")
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
    # what is served
    "DHCPLease",
    "BOOT_FIELDS",
    "DHCPOptions",
    "DHCPOptionCode",
    "PHASES",
    "OptionCodes",
    "option_codes",
    "PYDHCP_CODES",
    "plain_items",
    "UNSPECIFIED",
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
    "ConditionUnsupportedError",
    "ConditionMissingError",
]
