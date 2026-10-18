"""What a finished client's reservation becomes.

A client that is still handed a boot file after its install finishes **boots
the installer again**. Removing the reservation is one way out and the default,
but it throws away the fixed address. `Completion(keep=True)` keeps the entry and
replaces only what boots it: the header fields and `BOOT_OPTIONS`.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Union

from ._options import (
    PYDHCP_CODES,
    DHCPLease,
    DHCPOptionCode,
    OptionCodes,
    serves,
)
from .exceptions import ConfigError

__all__ = ["BOOT_OPTIONS", "Completion", "parse_completion"]

#: The options that make a client try to netboot, replaced or removed on
#: completion with the lease's `siaddr`, `sname` and `file`; everything else
#: about the reservation stays.
BOOT_OPTIONS = (DHCPOptionCode.BOOTFILE_NAME, DHCPOptionCode.TFTP_SERVER)


class Completion:
    """What to do with a reservation when provisioning finishes.

    `keep=False` (the default) removes it. `keep=True` keeps it, with its boot
    fields and options replaced by `lease`'s (none: the client falls through to
    its disk). `lease` is a `DHCPLease`, or a config mapping read with the
    `codes` codemap (`codes.lease`).
    """

    __slots__ = ("keep", "lease")

    def __init__(
        self,
        keep: bool = False,
        lease: "Union[DHCPLease, Mapping[Any, Any], None]" = None,
        codes: "Optional[type[OptionCodes]]" = None,
    ) -> None:
        self.keep = bool(keep)
        self.lease = (codes or PYDHCP_CODES).lease(lease)

    def __repr__(self) -> str:
        return f"Completion(keep={self.keep}, lease={self.lease!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Completion):
            return NotImplemented
        return self.keep == other.keep and self.lease == other.lease

    __hash__ = None  # type: ignore[assignment]

    def __bool__(self) -> bool:
        """True when completion does anything other than remove the entry."""
        return self.keep

    def to_mapping(self) -> Dict[str, Any]:
        """`{keep: false}`, or `{keep: true, lease: {...}}` with `lease` as
        `DHCPLease.to_mapping` writes it."""
        if not self.keep:
            return {"keep": False}
        return {"keep": True, "lease": self.lease.to_mapping()}

    def apply_to(self, lease: DHCPLease) -> DHCPLease:
        """The lease a kept entry should end up with.

        `BOOT_OPTIONS` are dropped and this completion's options put in their
        place, and its `siaddr`, `sname` and `file` replace the lease's --
        **replaced, not merged**. The address and every other option stay.
        """
        kept = lease.options.copy()
        kept.retain(code for code in kept if code not in BOOT_OPTIONS)
        kept.update(self.lease.options)
        return lease.replace(
            options=kept,
            siaddr=self.lease.siaddr,
            sname=self.lease.sname,
            file=self.lease.file,
        )


def parse_completion(
    declared: Any, where: str = "", codes: "Optional[type[OptionCodes]]" = None
) -> Optional[Completion]:
    """Build a `Completion` from `{keep: ..., options: ...}`, or from
    `{keep: ..., lease: ...}` as `Completion.to_mapping` writes it.

    `None` stays `None` (nothing declared). `where` names the declaring object
    in error messages; option names are read with the `codes` codemap
    (pydhcp's), a config's `options` by `codes.lease`.

    :raises ConfigError: the mapping cannot be used as given.
    """
    if declared is None:
        return None
    if not isinstance(declared, dict):
        raise ConfigError(
            f"dhcp_complete on {where!r} must be a mapping with `keep` and "
            f"`options`, got {type(declared).__name__}"
        )
    unknown = set(declared) - {"keep", "options", "lease"}
    if unknown or {"options", "lease"} <= set(declared):
        raise ConfigError(
            f"dhcp_complete on {where!r} has unknown key(s) "
            f"{', '.join(sorted(unknown or {'options', 'lease'}))}; it takes `keep` "
            f"and `options` (or `lease`)"
        )
    codes = codes or PYDHCP_CODES
    keep = declared.get("keep", False)
    if not isinstance(keep, bool):
        raise ConfigError(
            f"dhcp_complete.keep on {where!r} must be true or false, got {keep!r}"
        )
    try:
        if "lease" in declared:
            lease = codes.read_lease(declared["lease"])
        else:
            options = declared.get("options") or {}
            if not isinstance(options, dict):
                raise ConfigError(f"must be a mapping, got {type(options).__name__}")
            lease = codes.lease(options)
    except ConfigError as exc:
        raise ConfigError(f"dhcp_complete.options on {where!r}: {exc}") from exc
    if serves(lease) and not keep:
        raise ConfigError(
            f"dhcp_complete on {where!r} sets `options` but not `keep: true`; "
            f"options for a removed reservation have nowhere to go"
        )
    return Completion(keep=keep, lease=lease)
