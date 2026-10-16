"""What a finished client's reservation becomes.

A client that still receives `boot-file-name` after its install finishes **boots
the installer again**. Removing the reservation is one way out and the default,
but it throws away the fixed address. `Completion(keep=True)` keeps the entry and
replaces only the boot options (`BOOT_OPTIONS`).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from ._options import DHCPOptions, is_option
from .exceptions import ConfigError

__all__ = ["BOOT_OPTIONS", "Completion", "parse_completion"]

#: The options that make a client try to netboot: replaced or removed on
#: completion, everything else about the reservation stays.
BOOT_OPTIONS = ("boot-file-name", "next-server", "tftp-server-name")


class Completion:
    """What to do with a reservation when provisioning finishes.

    `keep=False` (the default) removes it. `keep=True` keeps it, with the boot
    options replaced by `options` (none: the client falls through to its disk).
    """

    __slots__ = ("keep", "options")

    def __init__(
        self, keep: bool = False, options: "Optional[Mapping[str, Any]]" = None
    ) -> None:
        self.keep = bool(keep)
        self.options = DHCPOptions(options or {})

    def __repr__(self) -> str:
        return f"Completion(keep={self.keep}, options={dict(self.options)!r})"

    def __bool__(self) -> bool:
        """True when completion does anything other than remove the entry."""
        return self.keep

    def apply_to(self, options: DHCPOptions) -> DHCPOptions:
        """The options a kept entry should end up with.

        The boot options are dropped and `self.options` put in their place --
        **replaced, not merged**.
        """
        kept = DHCPOptions(
            {k: v for k, v in options.items() if k not in BOOT_OPTIONS},
            raw=options.raw,
        )
        kept.update(self.options)
        return kept


def parse_completion(declared: Any, where: str = "") -> Optional[Completion]:
    """Build a `Completion` from a `{keep: ..., options: ...}` mapping.

    `None` stays `None` (nothing declared). `where` names the declaring object
    in error messages.

    :raises ConfigError: the mapping cannot be used as given.
    """
    if declared is None:
        return None
    if not isinstance(declared, dict):
        raise ConfigError(
            f"dhcp_complete on {where!r} must be a mapping with `keep` and "
            f"`options`, got {type(declared).__name__}"
        )
    unknown = set(declared) - {"keep", "options"}
    if unknown:
        raise ConfigError(
            f"dhcp_complete on {where!r} has unknown key(s) "
            f"{', '.join(sorted(unknown))}; it takes `keep` and `options`"
        )
    options = declared.get("options") or {}
    if not isinstance(options, dict):
        raise ConfigError(
            f"dhcp_complete.options on {where!r} must be a mapping, got "
            f"{type(options).__name__}"
        )
    for key in options:
        if not is_option(key):
            raise ConfigError(
                f"dhcp_complete.options on {where!r} has unknown dhcp option {key!r}"
            )
    keep = declared.get("keep", False)
    if not isinstance(keep, bool):
        raise ConfigError(
            f"dhcp_complete.keep on {where!r} must be true or false, got {keep!r}"
        )
    if options and not keep:
        raise ConfigError(
            f"dhcp_complete on {where!r} sets `options` but not `keep: true`; "
            f"options for a removed reservation have nowhere to go"
        )
    return Completion(keep=keep, options=options)
