"""Conditions: options a server hands out only to clients that match a test.

The case that drives this is the **iPXE chainload**: a PXE ROM must be handed
the iPXE binary and iPXE itself a script, and the discriminator is an option the
client sends (`user-class` is `iPXE`). Every server can do this and no two do it
the same way -- a Windows **policy**, a dhcpd **group** or `if`, a Kea **client
class** -- so a condition is declared once, under a **name**, and each backend
uses that name for its own construct.

A backend that cannot express a condition **fails** rather than arming without
it: a client that silently misses its chainload boots the installer again.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

from ._options import DHCPOptions, is_option
from .exceptions import ConfigError

__all__ = ["MATCH_KEYS", "NAME_CHARS", "Condition", "parse_conditions"]

#: `match` keys every backend can test, and the DHCP option each reads.
MATCH_KEYS = {
    "user-class": 77,
    "vendor-class": 60,
}

#: What a condition name may contain: it becomes a PowerShell argument, a dhcpd
#: identifier and a Kea class name, so it is kept to their intersection.
NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)


class Condition:
    """One named condition: a test, and the options to serve when it matches.

    `name` is the construct's name on every backend. `match` maps a key from
    `MATCH_KEYS` to the value the client must send; several keys mean all of
    them.
    """

    __slots__ = ("name", "match", "options")

    def __init__(
        self, name: str, match: "Mapping[str, Any]", options: "Mapping[str, Any]"
    ) -> None:
        self.name = name
        self.match = dict(match)
        self.options = DHCPOptions(options)

    def __repr__(self) -> str:
        return f"Condition({self.name!r}, match={self.match!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Condition):
            return NotImplemented
        return (
            self.name == other.name
            and self.match == other.match
            and dict(self.options) == dict(other.options)
        )

    @property
    def option_codes(self) -> Dict[int, Any]:
        """The match as `{option code: value}`, for a backend that tests by code."""
        return {MATCH_KEYS[key]: value for key, value in self.match.items()}


def parse_conditions(declared: Any, where: str = "") -> Dict[str, Condition]:
    """Build conditions from a `{name: {match: ..., options: ...}}` mapping.

    `where` names the declaring object in error messages.

    :raises ConfigError: the mapping cannot be used as given.
    """
    if not declared:
        return {}
    if not isinstance(declared, dict):
        raise ConfigError(
            f"dhcp_when on {where!r} must be a mapping of name -> condition, got "
            f"{type(declared).__name__}; each key is the policy/group/class name"
        )

    conditions: Dict[str, Condition] = {}
    for name, entry in declared.items():
        name = str(name)
        bad = set(name) - NAME_CHARS
        if not name or bad:
            raise ConfigError(
                f"dhcp_when name {name!r} on {where!r} may only contain letters, "
                f"digits, '-' and '_'"
                + (f" (found {''.join(sorted(bad))!r})" if bad else "")
            )
        if not isinstance(entry, dict):
            raise ConfigError(
                f"dhcp_when.{name} on {where!r} must be a mapping with `match` "
                f"and `options`, got {type(entry).__name__}"
            )
        unknown = set(entry) - {"match", "options"}
        if unknown:
            raise ConfigError(
                f"dhcp_when.{name} on {where!r} has unknown key(s) "
                f"{', '.join(sorted(unknown))}; it takes `match` and `options`"
            )
        match = entry.get("match") or {}
        if not isinstance(match, dict) or not match:
            raise ConfigError(
                f"dhcp_when.{name} on {where!r} needs a non-empty `match` "
                f"mapping; accepted keys: {', '.join(sorted(MATCH_KEYS))}"
            )
        for key in match:
            if key not in MATCH_KEYS:
                raise ConfigError(
                    f"dhcp_when.{name} on {where!r} cannot match on {key!r}; "
                    f"every backend must be able to test it, so the accepted "
                    f"keys are {', '.join(sorted(MATCH_KEYS))}"
                )
        options = entry.get("options") or {}
        if not isinstance(options, dict) or not options:
            raise ConfigError(
                f"dhcp_when.{name} on {where!r} needs a non-empty `options` "
                f"mapping -- a condition that serves nothing has no effect"
            )
        for key in options:
            if not is_option(key):
                raise ConfigError(
                    f"dhcp_when.{name} on {where!r} has unknown dhcp option {key!r}"
                )
        conditions[name] = Condition(name, match, options)
    return conditions
