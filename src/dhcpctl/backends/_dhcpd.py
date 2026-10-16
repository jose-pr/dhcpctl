"""ISC dhcpd backend, over OMAPI.

dhcpd cannot take a reservation without rewriting and reloading its config,
except over OMAPI, which is what this uses. Two things to know before relying on
it:

* the host object's `statements` are a fragment of dhcpd's **config language**,
  so every value interpolated into it is escaped or refused here;
* a host added over OMAPI is **not** written to `dhcpd.conf`, and survives a
  restart only if the server keeps it in a lease/host database. That is dhcpd's
  design.
"""

from __future__ import annotations

import logging
import re as _re
from typing import Any, List, Optional
from urllib.parse import urlsplit

from .._conditions import Condition
from .._model import Reservation, Target
from .._options import DHCPOptions
from .._server import DEFAULT_OWNER, DHCPServer, Secrets
from ..exceptions import BackendUnavailableError, ConfigError

__all__ = ["DHCPDBackend", "render_condition", "render_statements"]

LOGGER = logging.getLogger("dhcpctl")

#: Generic name -> what dhcpd calls it. `filename`/`next-server` are statements
#: in their own right; the rest are `option <name> <value>;`.
_STATEMENTS = {"boot-file-name": "filename", "next-server": "next-server"}
_OPTIONS = {
    "router": "routers",  # dhcpd's own spelling is plural
    "domain-name-servers": "domain-name-servers",
    "domain-name": "domain-name",
    "domain-search": "domain-search",
    "ntp-servers": "ntp-servers",
    "subnet-mask": "subnet-mask",
    "broadcast-address": "broadcast-address",
    "lease-time": "dhcp-lease-time",
    "tftp-server-name": "tftp-server-name",
    "host-name": "host-name",
    "vendor-class-identifier": "vendor-class-identifier",
}
#: Values dhcpd expects as quoted text rather than as an address or a number.
_TEXT = {
    "filename",
    "domain-name",
    "domain-search",
    "tftp-server-name",
    "host-name",
    "vendor-class-identifier",
}
#: What an unquoted value may contain: addresses, numbers, lists of them.
_BARE = _re.compile(r"^[0-9a-fA-F.:, ]+$")


class DHCPDBackend(DHCPServer):
    """`dhcpd://[keyname[:secret]@]host:7911/?keyname=&keyfile=/etc/dhcp/omapi.key`

    The key is the HMAC-MD5 secret matching `omapi-key`/`omapi-port` in
    `dhcpd.conf`. It is read from `keyfile=`, else the `omapi_key` secret: the
    URI's password, else the caller's. The key name is `keyname=`, else the
    `keyname` secret: the URI's user, else the caller's.
    `conditions=if` (default) writes conditions inline on the host;
    `conditions=group` puts the host in a group carrying them.
    """

    SETTINGS = frozenset({"keyname", "keyfile", "conditions"})
    URI_SECRETS = {"username": "keyname", "password": "omapi_key"}

    def __init__(
        self, uri: str, *, secrets: Secrets = None, owner: str = DEFAULT_OWNER
    ) -> None:
        super().__init__(uri, secrets=secrets, owner=owner)
        parts = urlsplit(uri)
        self.hostname = parts.hostname or "localhost"
        self.port = parts.port or 7911
        self.conditions = str(self.settings.get("conditions", "if")).lower()
        if self.conditions not in ("if", "group"):
            raise ConfigError(
                f"dhcpd: conditions must be 'if' or 'group', not "
                f"{self.conditions!r}"
            )
        self.keyfile = self.settings.get("keyfile")

    @property
    def keyname(self) -> Optional[str]:
        """The OMAPI key name: `keyname=`, else the `keyname` secret."""
        return self.settings.get("keyname") or self.secret("keyname")

    # -- transport --------------------------------------------------------

    def _key(self) -> Optional[str]:
        if self.keyfile:
            with open(self.keyfile, encoding="utf-8") as handle:
                return handle.read().strip()
        return self.secret("omapi_key")

    def omapi(self) -> Any:
        """An authenticated OMAPI connection to this dhcpd."""
        try:
            import pypureomapi
        except ImportError as exc:  # pragma: no cover - only without the extra
            raise BackendUnavailableError(
                "the ISC dhcpd backend requires the 'dhcpd' extra: "
                "pip install pydhcpctl[dhcpd]"
            ) from exc

        secret = self._key()
        if self.keyname and not secret:
            raise ConfigError(
                f"dhcpd: keyname={self.keyname!r} is set but no key was found; "
                f"give keyfile=<path>, a password in the URI, or the omapi_key "
                f"secret"
            )
        username = self.keyname.encode() if self.keyname else None
        key = secret.encode() if secret else None
        LOGGER.debug("omapi connect %s:%s", self.hostname, self.port)
        return pypureomapi.Omapi(self.hostname, self.port, username, key, timeout=30)

    # -- the DHCPServer contract ------------------------------------------

    def add(self, reservation: Reservation) -> None:
        target = reservation.target
        mac = _mac(target)
        conditions = list(reservation.conditions.values())
        extras = self.extras(reservation, "add")
        group = None
        if conditions and self.conditions == "group":
            # A host belongs to exactly one group, so one group carries every
            # condition that applies, named after them in declaration order.
            group = "-".join(c.name for c in conditions)
        elif conditions:
            extras = extras + [render_condition(c) for c in conditions]
        statements = render_statements(reservation.options, extras)
        connection = self.omapi()
        try:
            if group is not None:
                self._ensure_group(connection, group, conditions)
            connection.add_host_supersede(
                target.ip_text,
                mac,
                str(target.name),
                statements=statements or None,
            )
            if group is not None:
                # Set after the host exists: `change_group` takes the host name.
                connection.change_group(str(target.name), group)
        finally:
            _close(connection)

    def keep(self, reservation: Reservation) -> None:
        """Supersede the host with the completion statements instead of deleting it.

        `add_host_supersede` writes the host whole, so there is no window where
        the host has the installer's filename and the new statements half applied.
        """
        target = reservation.target
        options = reservation.completion.apply_to(reservation.options)
        statements = render_statements(options, self.extras(reservation, "remove"))
        connection = self.omapi()
        try:
            connection.add_host_supersede(
                target.ip_text,
                _mac(target),
                str(target.name),
                statements=statements or None,
            )
        finally:
            _close(connection)

    def _ensure_group(
        self, connection: Any, group: str, conditions: List[Condition]
    ) -> None:
        """Create the group carrying these conditions, unless it is already there.

        OMAPI has no group lookup, so "already there" is what `add_group` raising
        says. An OMAPI group does not survive a restart; `condition_recipe` prints
        the `dhcpd.conf` block that does.
        """
        statements = " ".join(render_condition(c) for c in conditions)
        try:
            connection.add_group(group, statements)
        except Exception as exc:  # noqa: BLE001 - the library raises its own types
            if "exist" not in str(exc).lower() and type(exc).__name__ not in (
                "OmapiError",
                "OmapiErrorNotFound",
            ):
                raise
            LOGGER.debug("dhcpd group %s already present (%s)", group, exc)

    def ensure_condition(self, reservation: Reservation, condition: Condition) -> str:
        """dhcpd expresses a condition in the statements it already writes.

        Nothing to create in `if` mode; in `group` mode the group is created with
        the host, because `change_group` needs the host to exist first.
        """
        return condition.name

    def condition_recipe(self, reservation: Reservation, condition: Condition) -> str:
        """The `dhcpd.conf` group an admin can add, the durable alternative."""
        return (
            f"# {self.owner}: add to dhcpd.conf so {condition.name!r} survives a "
            f"restart\n"
            f'group "{condition.name}" {{\n'
            f"  {render_condition(condition)}\n"
            f"}}"
        )

    def remove_condition_member(
        self, reservation: Reservation, condition: Condition
    ) -> None:
        """Drop the host out of its group, leaving the group for other hosts.

        OMAPI has no "unset the group" operation; superseding the host without
        one is the way.
        """
        if self.conditions != "group":
            return
        target = reservation.target
        connection = self.omapi()
        try:
            connection.add_host_supersede(
                target.ip_text,
                _mac(target),
                str(target.name),
                statements=None,
            )
        finally:
            _close(connection)

    def remove(self, reservation: Reservation) -> None:
        mac = _mac(reservation.target)
        connection = self.omapi()
        try:
            connection.del_host(mac)
        except Exception as exc:  # noqa: BLE001 - the library's own not-found type
            if type(exc).__name__ != "OmapiErrorNotFound":
                raise
            LOGGER.debug("omapi: no host for %s; nothing to remove", mac)
        finally:
            _close(connection)


def _close(connection: Any) -> None:
    try:
        connection.close()
    except Exception:  # pragma: no cover - closing must not mask the real error
        LOGGER.debug("omapi close failed", exc_info=True)


def _mac(target: Target) -> str:
    return str(target.require_mac("a dhcpd host reservation is identified by one"))


#: `match` key -> the dhcpd expression that tests it. `exists` first, because
#: testing an absent option is an error in dhcpd, not false.
_CONDITION_TESTS = {
    "user-class": "exists user-class and option user-class = {value}",
    "vendor-class": (
        "exists vendor-class-identifier and " "option vendor-class-identifier = {value}"
    ),
}


def render_condition(condition: Condition) -> str:
    """One condition as a dhcpd `if` statement, values escaped.

    The body goes through the same renderer as the host's own options, so a
    conditional option cannot be escaped differently from an unconditional one.
    """
    tests = []
    for key, value in condition.match.items():
        text = str(value)
        if any(ch in text for ch in '\r\n\x00"'):
            raise ConfigError(
                f"dhcp_when.{condition.name} cannot match {key} on {text!r}: a "
                "newline, NUL or quote cannot appear in a dhcpd test"
            )
        tests.append(_CONDITION_TESTS[key].format(value=_quote_text(text)))
    body = render_statements(condition.options)
    return "if " + " and ".join(tests) + " { " + body + " }"


def render_statements(options: DHCPOptions, raw: Optional[List[Any]] = None) -> str:
    """Render options as a dhcpd config fragment, escaping every value.

    `statements` is config *source*, so an unescaped value could end one
    statement and start another. Text values are quoted with `"` and `\\`
    escaped; anything meant to be an address or a number must look like one.
    `raw` fragments are appended verbatim.
    """
    parts: List[str] = []
    for name, value in options.items():
        keyword = _STATEMENTS.get(name)
        if keyword:
            parts.append(f"{keyword} {_render(keyword, value)};")
            continue
        option = _OPTIONS.get(name)
        if option is None:
            if name.startswith("option-"):
                option = f"dhcp-option-{name[len('option-'):]}"
            elif name.isdigit():
                option = f"dhcp-option-{name}"
            else:  # pragma: no cover - unknown names are refused earlier
                continue
        parts.append(f"option {option} {_render(option, value)};")
    parts.extend(str(line) for line in (raw or []))
    return " ".join(parts)


def _quote_text(text: str) -> str:
    """A dhcpd string literal. The one place `"` and `\\` are escaped."""
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _render(keyword: str, value: Any) -> str:
    """One value, quoted or bare, never able to end its statement."""
    if isinstance(value, (list, tuple)):
        return ", ".join(_render(keyword, item) for item in value)
    text = str(value)
    if any(ch in text for ch in "\r\n\x00"):
        raise ConfigError(
            f"dhcpd option {keyword!r} value contains a newline or NUL, which "
            "cannot be written into a dhcpd statement: " + repr(text)
        )
    if keyword in _TEXT:
        return _quote_text(text)
    if not _BARE.match(text):
        raise ConfigError(
            f"dhcpd option {keyword!r} expects an address or number, got "
            f"{text!r}; quote it as text by using a text option, or pass it "
            "through raw.dhcpd if you know what dhcpd expects"
        )
    return text
