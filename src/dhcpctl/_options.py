"""What a server serves is pydhcp's: a `DHCPLease`, read from a config by a codemap.

A lease holds the client's address, its options (pydhcp's `DHCPOptions`) and
the BOOTP header fields a reply carries beside them: `siaddr` (the next server
to boot from), `sname` and `file` (the boot file). Code names an option by
code: `options[DHCPOptionCode.ROUTER]`, `options[3]`.

Names belong to configs. A codemap -- pydhcp's `DHCPOptionCode` names as an
`OptionCodes` enum, plus the names a config declares -- reads them, and a bag
built with it (`DHCPOptions(codemap=...)`) decodes with the types it declares:

    options:
      my-option: {code: 224, type: String}   # an option of the config's own
      domain-name-servers: dns               # an alias of a name...
      routers: 3                             # ...or of a code
      boot-file-name: file                   # ...or of a header field

A name is read by pydhcp's `resolve`: a member name in any case, `-` or `_`
alike (`bootfile-name`), `option-<n>` or a number. A value is a Python object
the option's codec accepts, and stays one: a backend decides how to write it
for its server.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

import pydhcp.options as _pydhcp
from pydhcp.lease import DHCPLease
from pydhcp.options import (
    DHCPOptionCode,
    DHCPOptions,
    DHCPOptionType,
    OptionCodeEnum,
)
from pydhcp.packet import UNSPECIFIED_ADDRESS as UNSPECIFIED

from .exceptions import ConfigError

__all__ = [
    "BOOT_FIELDS",
    "DHCPLease",
    "DHCPOptionCode",
    "DHCPOptions",
    "PHASES",
    "OptionCodes",
    "option_codes",
    "PYDHCP_CODES",
    "plain_items",
    "UNSPECIFIED",
]

#: The BOOTP header fields a lease carries beside its options, by the names a
#: config gives them: pydhcp's, and `next-server`, which servers call `siaddr`.
BOOT_FIELDS = {
    "siaddr": "siaddr",
    "next-server": "siaddr",
    "sname": "sname",
    "file": "file",
}

#: The phases of `Reservation.extras` and `DHCPServer.extras`.
PHASES = ("add", "remove")


def _member(name: Any) -> str:
    """A name as an enum member name: `bootfile-name` is `BOOTFILE_NAME`."""
    return str(name).strip().upper().replace("-", "_")


#: pydhcp's codec classes by lower-case name, for a declared option's `type`.
_TYPES: Dict[str, type] = {
    name.lower(): value
    for name, value in vars(_pydhcp).items()
    if isinstance(value, type) and issubclass(value, DHCPOptionType)
}

_LIST_TYPE = re.compile(r"^list\[(\w+)\]$")


def _codec(text: str, where: str) -> type:
    """The pydhcp codec a declared `type` names: `String`, `List[IPv4AddressOption]`."""
    spelled = str(text).strip().lower()
    listed = _LIST_TYPE.match(spelled)
    codec = _TYPES.get(listed.group(1) if listed else spelled)
    if codec is None:
        raise ConfigError(
            f"{where}: unknown option type {text!r}; a pydhcp codec name, e.g. "
            f"String, U32, IPv4AddressOption, or List[...] of one"
        )
    return _pydhcp.List[codec] if listed else codec


class OptionCodes(OptionCodeEnum):
    """A codemap: pydhcp's option codes and names, and what a config declares.

    Build one with `option_codes`; `PYDHCP_CODES` is pydhcp's names alone. As
    a pydhcp `OptionCodeEnum`, each codemap has its own codecs and its own
    unnamed members, so a declared type never reaches pydhcp's registry.
    Names are read by pydhcp's `resolve`.
    """

    @classmethod
    def field(cls, name: Any) -> Optional[str]:
        """The lease header field `name` names (`next-server` is `siaddr`), or None."""
        if not isinstance(name, str):
            return None
        return cls._fields.get(_member(name))

    @classmethod
    def knows(cls, name: Any) -> bool:
        """Does `name` name an option or a header field of this codemap?"""
        if cls.field(name):
            return True
        try:
            cls.resolve(name)
        except (TypeError, ValueError):
            return False
        return True

    @classmethod
    def options(
        cls, declared: "Union[Mapping[Any, Any], DHCPOptions, None]", where: str = ""
    ) -> DHCPOptions:
        """A bag with this codemap from a mapping of option names to values.

        pydhcp's `DHCPOptions.from_mapping` reads it: a value is what the codec
        takes, an enum its member name, octets `{"hex": ...}` or, for an
        opaque option, hex text. A `DHCPOptions` is copied, keeping its own
        codemap.

        :raises ConfigError: an unknown name, or a value its option's codec
            refuses (pydhcp's message, and ` (on 'where')`).
        """
        if isinstance(declared, DHCPOptions):
            return declared.copy()
        try:
            return DHCPOptions.from_mapping(declared or {}, codemap=cls)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{exc}{_on(where)}") from exc

    @classmethod
    def lease(
        cls, declared: "Union[Mapping[Any, Any], DHCPLease, None]", where: str = ""
    ) -> DHCPLease:
        """What a config mapping serves: its options, and the header fields
        (`next-server`, `file`, ...) among them, as a lease with no address.

        A `DHCPLease` is returned as it is.

        :raises ConfigError: an unknown name, or a value its option or field
            refuses.
        """
        if isinstance(declared, DHCPLease):
            return declared
        fields: Dict[str, Any] = {}
        options: Dict[Any, Any] = {}
        for name, value in (declared or {}).items():
            field = cls.field(name)
            if field:
                if value not in (None, ""):
                    fields[field] = value
            else:
                options[name] = value
        try:
            return DHCPLease(
                UNSPECIFIED, options=cls.options(options, where), strict=False, **fields
            )
        except (TypeError, ValueError) as exc:
            if isinstance(exc, ConfigError):
                raise
            raise ConfigError(f"{exc}{_on(where)}") from exc

    @classmethod
    def read_lease(cls, data: Any, where: str = "") -> DHCPLease:
        """A lease from what `DHCPLease.to_mapping` writes, its address optional.

        :raises ConfigError: what pydhcp refuses, with its message.
        """
        try:
            return DHCPLease.from_mapping(data or {}, codemap=cls, strict=False)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{exc}{_on(where)}") from exc

    @classmethod
    def over(cls, base: "type[OptionCodes]") -> "type[OptionCodes]":
        """This codemap's declarations, every layer of them, made over `base`."""
        stacked = base
        for declared in cls._layers:
            stacked = option_codes(declared, base=stacked)
        return stacked

    @staticmethod
    def of(codes: Any) -> "type[OptionCodes]":
        """`codes` as a codemap: itself, a declarations mapping, or pydhcp's."""
        if isinstance(codes, type) and issubclass(codes, OptionCodes):
            return codes
        return option_codes(codes) if codes else PYDHCP_CODES


def _on(where: str) -> str:
    return f" (on {where!r})" if where else ""


def option_codes(
    declared: "Optional[Mapping[str, Any]]" = None,
    *,
    base: "Optional[type[OptionCodes]]" = None,
) -> "type[OptionCodes]":
    """A codemap: `base`'s members (pydhcp's by default) and `declared`'s.

    `declared` maps a name to `{code: <n>, type: <pydhcp codec name>}` (an
    option of the caller's own; `type` applies to this codemap only), or to a
    code, another name or a header field (an alias). Every declaration is
    checked here.

    :raises ConfigError: an unknown key or type, a code pydhcp refuses, a name
        that cannot be one (a header field, `option-<n>`, a number, not a
        Python identifier), a pydhcp name given another code, an alias of
        nothing, or a loop.
    """
    source = DHCPOptionCode if base is None else base
    members = {name: int(member) for name, member in source.__members__.items()}
    fields: Dict[str, str] = (
        {_member(name): field for name, field in BOOT_FIELDS.items()}
        if base is None
        else dict(base._fields)
    )
    types: Dict[int, type] = {}
    entries: Dict[str, Any] = {}
    written: Dict[str, str] = {}
    for name, entry in (declared or {}).items():
        where = f"options.{name}"
        key = _member(name)
        if key in written:
            raise ConfigError(
                f"{where}: {name!r} and {written[key]!r} are one name, declared twice"
            )
        written[key] = str(name)
        if (
            _member(name) in {_member(field) for field in BOOT_FIELDS}
            or key.replace("OPTION_", "", 1).isdigit()
            or not key.isidentifier()
        ):
            raise ConfigError(f"{where}: {name!r} cannot be declared as a name")
        if isinstance(entry, Mapping):
            unknown = set(entry) - {"code", "type"}
            if unknown or "code" not in entry:
                raise ConfigError(
                    f"{where} takes `code` and an optional `type`"
                    + (f", not {', '.join(sorted(unknown))}" if unknown else "")
                )
            raw = entry["code"]
            if isinstance(raw, bool) or not isinstance(raw, (int, str)):
                raise ConfigError(f"{where}.code must be an option code, not {raw!r}")
            try:
                code = int(DHCPOptionCode.from_code(int(raw)))
            except ValueError as exc:
                raise ConfigError(f"{where}.code: {exc}") from exc
            if "type" in entry:
                types[code] = _codec(entry["type"], where)
            entries[key] = code
        elif isinstance(entry, (int, str)) and not isinstance(entry, bool):
            entries[key] = entry
        else:
            raise ConfigError(
                f"{where} must be a code, a name or {{code:, type:}}, got "
                f"{type(entry).__name__}"
            )

    def code_of(key: str, seen: Tuple[str, ...], shown: Any = "") -> Any:
        """The code `key` names, or the header field it names, as a str."""
        entry = entries.get(key)
        if entry is None:
            if key in fields:
                return fields[key]
            try:
                return int(source.resolve(shown or key))
            except ValueError:
                raise ConfigError(f"no option {shown or key!r} to alias") from None
        if isinstance(entry, int):
            return entry
        if key in seen:
            chain = [written.get(k, k) for k in seen + (key,)]
            raise ConfigError(f"option names {' -> '.join(chain)} loop")
        return code_of(_member(entry), seen + (key,), entry)

    resolved = {}
    for key in entries:
        name = written[key]
        try:
            code = code_of(key, ())
        except (ConfigError, ValueError) as exc:
            raise ConfigError(f"options.{name}: {exc}") from exc
        known = DHCPOptionCode.__members__.get(key)
        if known is not None and int(known) != code:
            raise ConfigError(
                f"options.{name}: {name!r} is pydhcp's name for option "
                f"{int(known)}, not {code}"
            )
        if isinstance(code, str):
            fields[key] = code
            members.pop(key, None)
        else:
            resolved[key] = code
            fields.pop(key, None)
    members.update(resolved)
    codemap = OptionCodes("OptionCodes", list(members.items()), module=__name__)
    for code in range(256):
        codemap(code).register_type(types.get(code) or source(code).get_type())
    codemap._fields = fields
    layers = () if base is None else base._layers
    codemap._layers = layers + ((dict(declared),) if declared else ())
    return codemap


#: pydhcp's names, with nothing declared.
PYDHCP_CODES = option_codes()


def serves(lease: DHCPLease) -> bool:
    """Does `lease` hand a client anything: an option or a boot field?"""
    return bool(
        len(lease.options)
        or not lease.siaddr.is_unspecified
        or lease.sname
        or lease.file
    )


def plain_items(options: DHCPOptions) -> List[Tuple[Any, Any]]:
    """`(code, value)` with each value as plain data (`codec.to_json()`).

    A helper for a backend that writes text: a list option a list of strings
    (`["10.0.0.1"]`), a number an `int`, an opaque option hex text.
    """
    return [(code, _plain(value)) for code, value in options.items()]


def _plain(value: Any) -> Any:
    data = value.to_json() if hasattr(value, "to_json") else value
    return list(data) if isinstance(data, list) else data
