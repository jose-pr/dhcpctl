"""ISC dhcpd backend, over OMAPI.

dhcpd cannot take a reservation without rewriting and reloading its config,
except over OMAPI, which is what this uses. Two things to know before relying on
it:

* the host object's `statements` are a fragment of dhcpd's **config language**,
  so every value interpolated into it is escaped or refused here;
* a host or group added over OMAPI is **not** written to `dhcpd.conf`: dhcpd
  keeps it in its leases file, so it survives a restart that keeps that file.
"""

from __future__ import annotations

import logging
import re as _re
import struct as _struct
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from pydhcp.options import Bytes, DomainList, DomainName, OctetString, String

from .._conditions import Condition
from .._model import Reservation, Target
from .._options import UNSPECIFIED, DHCPLease, DHCPOptionCode, plain_items
from .._server import DEFAULT_OWNER, DHCPServer, Secrets
from ..exceptions import BackendUnavailableError, ConfigError, ServerError

__all__ = ["DHCPDBackend", "render_condition", "render_statements"]

LOGGER = logging.getLogger("dhcpctl")

#: The lease's BOOTP header fields, by the dhcpd statement that sets each;
#: `siaddr` is an address, the others text.
_STATEMENTS = (
    ("file", "filename"),
    ("sname", "server-name"),
    ("siaddr", "next-server"),
)
#: Option code -> dhcpd's name for it: every code ISC dhcpd 4.4 defines (what
#: `dhcpd -t` reports when `unknown-<n>` is redefined). A value for one of these
#: is written in that option's own syntax; any other code is `unknown-<n>`,
#: which dhcpd(8) takes as opaque octets. Writing `unknown-<n>` for a code dhcpd
#: knows makes it parse the value as that option's type, and refuse octets.
_OPTIONS = {
    1: "subnet-mask",
    2: "time-offset",
    3: "routers",
    4: "time-servers",
    5: "ien116-name-servers",
    6: "domain-name-servers",
    7: "log-servers",
    8: "cookie-servers",
    9: "lpr-servers",
    10: "impress-servers",
    11: "resource-location-servers",
    12: "host-name",
    13: "boot-size",
    14: "merit-dump",
    15: "domain-name",
    16: "swap-server",
    17: "root-path",
    18: "extensions-path",
    19: "ip-forwarding",
    20: "non-local-source-routing",
    21: "policy-filter",
    22: "max-dgram-reassembly",
    23: "default-ip-ttl",
    24: "path-mtu-aging-timeout",
    25: "path-mtu-plateau-table",
    26: "interface-mtu",
    27: "all-subnets-local",
    28: "broadcast-address",
    29: "perform-mask-discovery",
    30: "mask-supplier",
    31: "router-discovery",
    32: "router-solicitation-address",
    33: "static-routes",
    34: "trailer-encapsulation",
    35: "arp-cache-timeout",
    36: "ieee802-3-encapsulation",
    37: "default-tcp-ttl",
    38: "tcp-keepalive-interval",
    39: "tcp-keepalive-garbage",
    40: "nis-domain",
    41: "nis-servers",
    42: "ntp-servers",
    43: "vendor-encapsulated-options",
    44: "netbios-name-servers",
    45: "netbios-dd-server",
    46: "netbios-node-type",
    47: "netbios-scope",
    48: "font-servers",
    49: "x-display-manager",
    50: "dhcp-requested-address",
    51: "dhcp-lease-time",
    52: "dhcp-option-overload",
    53: "dhcp-message-type",
    54: "dhcp-server-identifier",
    55: "dhcp-parameter-request-list",
    56: "dhcp-message",
    57: "dhcp-max-message-size",
    58: "dhcp-renewal-time",
    59: "dhcp-rebinding-time",
    60: "vendor-class-identifier",
    61: "dhcp-client-identifier",
    62: "nwip-domain",
    63: "nwip-suboptions",
    64: "nisplus-domain",
    65: "nisplus-servers",
    66: "tftp-server-name",
    67: "bootfile-name",
    68: "mobile-ip-home-agent",
    69: "smtp-server",
    70: "pop-server",
    71: "nntp-server",
    72: "www-server",
    73: "finger-server",
    74: "irc-server",
    75: "streettalk-server",
    76: "streettalk-directory-assistance-server",
    77: "user-class",
    78: "slp-directory-agent",
    79: "slp-service-scope",
    81: "fqdn",
    82: "relay-agent-information",
    85: "nds-servers",
    86: "nds-tree-name",
    87: "nds-context",
    88: "bcms-controller-names",
    89: "bcms-controller-address",
    91: "client-last-transaction-time",
    92: "associated-ip",
    93: "pxe-system-type",
    94: "pxe-interface-id",
    97: "pxe-client-id",
    99: "geoconf-civic",
    100: "pcode",
    101: "tcode",
    108: "v6-only-preferred",
    112: "netinfo-server-address",
    113: "netinfo-server-tag",
    114: "default-url",
    116: "auto-config",
    117: "name-service-search",
    118: "subnet-selection",
    119: "domain-search",
    121: "classless-static-routes",
    124: "vivco",
    125: "vivso",
    136: "pana-agent",
    137: "v4-lost",
    138: "capwap-ac-v4",
    141: "sip-ua-cs-domains",
    142: "ipv4-address-andsf",
    146: "rdnss-selection",
    150: "tftp-server-address",
    159: "v4-portparams",
    160: "v4-captive-portal",
    209: "loader-configfile",
    210: "loader-pathprefix",
    211: "loader-reboottime",
    212: "option-6rd",
    213: "v4-access-domain",
}

#: pydhcp codecs whose values dhcpd takes as quoted text, not as an address or
#: a number.
_TEXT_CODECS = (String, OctetString, DomainList)
#: Codes pydhcp takes as octets that dhcpd defines with a structure of its own
#: (text, addresses, a flag and addresses): `dhcpd -t` refuses octets for them.
_STRUCTURED = frozenset({62, 77, 78, 79, 85, 86, 87, 98, 136, 137, 159, 212})
#: Flags dhcpd defines as a number, not as `true`/`false`.
_FLAG_AS_NUMBER = frozenset({116})
#: What an unquoted value may contain: addresses, numbers, lists of them.
_BARE = _re.compile(r"^(true|false|-?[0-9a-fA-F.:, ]+)$")
#: A domain name as dhcpd takes one: bare, with no trailing dot.
_DOMAIN = _re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$")


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
    #: dhcpd's spellings, so a dhcpd config's names (`routers`, `filename`) work.
    OPTION_NAMES = {
        **{
            name: int(code)
            for code, name in _OPTIONS.items()
            if name.replace("-", "_").upper() not in DHCPOptionCode.__members__
        },
        **{name: field for field, name in _STATEMENTS if name != "next-server"},
    }
    URI_SECRETS = {"username": "keyname", "password": "omapi_key"}

    def __init__(
        self,
        uri: str,
        *,
        secrets: Secrets = None,
        owner: str = DEFAULT_OWNER,
        codes: Any = None,
    ) -> None:
        super().__init__(uri, secrets=secrets, owner=owner, codes=codes)
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

    def _recording(self, sent: List[str]) -> Any:
        """Each OMAPI call, with its arguments; dhcpd holds no group yet."""
        return self._replaced(omapi=lambda: _RecordedOmapi(sent))

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
        return _connection_class(pypureomapi)(
            self.hostname, self.port, username, key, timeout=30
        )

    # -- the DHCPServer contract ------------------------------------------

    def add(self, reservation: Reservation) -> None:
        conditions = list(reservation.conditions.values())
        extras = self.extras(reservation, "add")
        group = None
        if conditions and self.conditions == "group":
            # A host belongs to exactly one group, so one group carries every
            # condition that applies, named after them in declaration order.
            group = "-".join(c.name for c in conditions)
        elif conditions:
            extras = extras + [render_condition(c) for c in conditions]
        if group is not None:
            # A host's own statements outrank its group's, so what a condition
            # overrides is the host's only when no condition matches.
            statements = render_guarded(reservation.lease, conditions, extras)
        else:
            statements = render_statements(reservation.lease, extras)
        host = _host(reservation)
        connection = self.omapi()
        try:
            if group is not None:
                self._ensure_group(connection, group, conditions)
            # Re-arming replaces the client's host: OMAPI creates a host only
            # when there is none, and cannot rewrite one's statements in place.
            _delete_host(connection, host[1])
            # The group is set in the same create: a host that exists, even for
            # a moment, without it is a client served without its condition.
            connection.create_host(*host, statements=statements, group=group)
        finally:
            _close(connection)

    def keep(self, reservation: Reservation) -> None:
        """Rewrite the host with the completion's lease applied.

        dhcpd refuses to create a host that exists, and OMAPI cannot replace a
        host's statements in place, so the host is deleted and created again:
        for that moment the client has no reservation, which is not a boot.
        """
        statements = render_statements(
            reservation.completion.apply_to(reservation.lease),
            self.extras(reservation, "remove"),
        )
        self._rewrite(reservation, statements)

    def _rewrite(self, reservation: Reservation, statements: str) -> None:
        host = _host(reservation)
        connection = self.omapi()
        try:
            _delete_host(connection, host[1])
            connection.create_host(*host, statements=statements)
        finally:
            _close(connection)

    def _ensure_group(
        self, connection: Any, group: str, conditions: List[Condition]
    ) -> None:
        """Use the group carrying these conditions, or create it.

        dhcpd keeps an OMAPI group in its leases file; `condition_recipe`
        prints the `dhcpd.conf` block for a server whose leases file is not kept.

        :raises ServerError: the group is not there and cannot be created.
        """
        if connection.group_exists(group):
            LOGGER.debug("dhcpd group %s already present", group)
            return
        statements = " ".join(render_condition(c) for c in conditions)
        try:
            connection.add_group(group, statements)
        except Exception as exc:  # noqa: BLE001 - the library raises its own types
            raise ServerError(
                f"dhcpd refused to create group {group!r} ({exc}); the host is not "
                f"armed, because without the group it would be served without its "
                f"conditions. Add the group to dhcpd.conf (see condition_recipe)."
            ) from exc

    def ensure_condition(self, reservation: Reservation, condition: Condition) -> str:
        """dhcpd expresses a condition in the statements it already writes.

        Nothing to create in `if` mode; in `group` mode the group is created with
        the host, because `change_group` needs the host to exist first.
        """
        return condition.name

    def condition_recipe(self, reservation: Reservation, condition: Condition) -> str:
        """The `dhcpd.conf` group an admin can add, for when OMAPI cannot create it."""
        return (
            f"# {self.owner}: add to dhcpd.conf so {condition.name!r} need not be "
            f"created over OMAPI\n"
            f'group "{condition.name}" {{\n'
            f"  {render_condition(condition)}\n"
            f"}}"
        )

    def remove_condition_member(
        self, reservation: Reservation, condition: Condition
    ) -> None:
        """Drop the host out of its group, leaving the group for other hosts.

        OMAPI cannot unset a host's group, so the host is created again without
        one, serving the reservation's own lease.
        """
        if self.conditions != "group":
            return
        self._rewrite(
            reservation,
            render_statements(reservation.lease, self.extras(reservation, "add")),
        )

    def remove(self, reservation: Reservation) -> None:
        mac = _mac(reservation.target)
        connection = self.omapi()
        try:
            _delete_host(connection, mac)
        finally:
            _close(connection)


class _RecordedOmapi:
    """Stands in for an OMAPI connection: each call becomes a line of `sent`."""

    def __init__(self, sent: List[str]) -> None:
        self._sent = sent

    def __getattr__(self, name: str) -> Any:
        def call(*args: Any, **kwargs: Any) -> None:
            if name != "close":
                lines = [" ".join([name, *map(str, args)])]
                lines += [
                    f"  {key}: {value}"
                    for key, value in kwargs.items()
                    if value is not None
                ]
                self._sent.append("\n".join(lines))

        return call


def _host(reservation: Reservation) -> Tuple[str, str, str]:
    """The host's address, MAC and name, as OMAPI takes them."""
    ip = str(reservation.require_ip("a dhcpd host carries a fixed address"))
    return ip, _mac(reservation.target), str(reservation.target.name)


_CONNECTIONS: Dict[Any, type] = {}


def _connection_class(pypureomapi: Any) -> type:
    """pypureomapi's connection, with the two calls it lacks.

    Made on first use, so importing this module needs no pypureomapi.
    """
    if pypureomapi.Omapi in _CONNECTIONS:
        return _CONNECTIONS[pypureomapi.Omapi]

    class Connection(pypureomapi.Omapi):
        def create_host(
            self,
            ip: str,
            mac: str,
            name: str,
            statements: str = "",
            group: Optional[str] = None,
        ) -> None:
            """Create a host, in `group` when given; one that exists is refused.

            :raises ServerError: dhcpd did not create it (a host with this name
                or MAC exists, or a statement was refused).
            """
            message = pypureomapi.OmapiMessage.open(b"host")
            message.message.append((b"create", _struct.pack("!I", 1)))
            message.message.append((b"exclusive", _struct.pack("!I", 1)))
            message.obj.append((b"name", name.encode("utf-8")))
            message.obj.append((b"hardware-address", pypureomapi.pack_mac(mac)))
            message.obj.append((b"hardware-type", _struct.pack("!I", 1)))
            message.obj.append((b"ip-address", pypureomapi.pack_ip(ip)))
            if group:
                message.obj.append((b"group", group.encode("utf-8")))
            if statements:
                message.obj.append((b"statements", statements.encode("utf-8")))
            if self.query_server(message).opcode != pypureomapi.OMAPI_OP_UPDATE:
                raise ServerError(
                    f"dhcpd refused to create host {name!r} ({ip}): it exists, "
                    f"or a statement was refused"
                )

        def group_exists(self, name: str) -> bool:
            """Does dhcpd hold a group by this name? An open without create."""
            message = pypureomapi.OmapiMessage.open(b"group")
            message.obj.append((b"name", name.encode("utf-8")))
            return self.query_server(message).opcode == pypureomapi.OMAPI_OP_UPDATE

    _CONNECTIONS[pypureomapi.Omapi] = Connection
    return Connection


def _delete_host(connection: Any, mac: str) -> None:
    """Delete the host for `mac`; none is success, so cleanup can re-run."""
    try:
        connection.del_host(mac)
    except Exception as exc:  # noqa: BLE001 - the library's own not-found type
        if type(exc).__name__ != "OmapiErrorNotFound":
            raise
        LOGGER.debug("omapi: no host for %s; nothing to remove", mac)


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
    body = render_statements(condition.lease)
    return "if " + _test(condition) + " { " + body + " }"


def _test(condition: Condition) -> str:
    """The dhcpd expression true for a client this condition matches."""
    tests = []
    for key, value in condition.match.items():
        text = str(value)
        if any(ch in text for ch in '\r\n\x00"'):
            raise ConfigError(
                f"dhcp_when.{condition.name} cannot match {key} on {text!r}: a "
                "newline, NUL or quote cannot appear in a dhcpd test"
            )
        tests.append(_CONDITION_TESTS[key].format(value=_quote_text(text)))
    return " and ".join(tests)


#: The lease's header fields, by the key `_served` names them with.
_FIELDS = ("file", "sname", "siaddr")


def _served(lease: DHCPLease) -> List[Any]:
    """What `lease` sets: its option codes, and the header fields it fills."""
    keys: List[Any] = [int(code) for code in lease.options]
    keys += [f for f in _FIELDS if f != "siaddr" and getattr(lease, f)]
    if not lease.siaddr.is_unspecified:
        keys.append("siaddr")
    return keys


def _part(lease: DHCPLease, keys: "set[Any]", keep: bool) -> DHCPLease:
    """`lease` with only the `keys` (`keep`), or without them."""
    options = lease.options.copy()
    options.retain(code for code in options if (int(code) in keys) == keep)
    fields = {
        f: (
            getattr(lease, f)
            if (f in keys) == keep
            else ("" if f != "siaddr" else UNSPECIFIED)
        )
        for f in _FIELDS
    }
    return lease.replace(options=options, **fields)


def render_guarded(
    lease: DHCPLease, conditions: List[Condition], extras: Optional[List[Any]] = None
) -> str:
    """A host's statements when its conditions live in a group.

    dhcpd evaluates a host's statements after its group's, so each value a
    condition overrides goes in the `else` of its conditions' tests, and the
    group's conditional value wins for a client that matches. `else`, not
    `if not`: a test on an option the client did not send is neither true nor
    false, and `not` of it is not true either.
    """
    overriding: Dict[Any, Tuple[str, ...]] = {}
    for condition in conditions:
        for key in _served(condition.lease):
            overriding[key] = overriding.get(key, ()) + (condition.name,)
    by_name = {c.name: c for c in conditions}
    guards: Dict[Tuple[str, ...], "set[Any]"] = {}
    for key, names in overriding.items():
        guards.setdefault(names, set()).add(key)
    parts = [render_statements(_part(lease, set(overriding), keep=False))]
    for names, keys in guards.items():
        body = render_statements(_part(lease, keys, keep=True))
        if body:
            test = " or ".join(f"({_test(by_name[n])})" for n in names)
            parts.append(f"if {test} {{ }} else {{ {body} }}")
    parts.extend(str(line) for line in (extras or []))
    return " ".join(part for part in parts if part)


def render_statements(lease: DHCPLease, extras: Optional[List[Any]] = None) -> str:
    """Render what `lease` serves as a dhcpd config fragment, escaping every value.

    `statements` is config *source*, so an unescaped value could end one
    statement and start another. Text values are quoted with `"` and `\\`
    escaped; anything meant to be an address or a number must look like one.
    The options come first, then the header fields (`filename`, `server-name`,
    `next-server`); `extras` are appended verbatim.
    """
    parts: List[str] = []
    for key, value in plain_items(lease.options):
        codec = key.get_type()
        text = issubclass(codec, _TEXT_CODECS)
        if int(key) in _STRUCTURED and issubclass(codec, Bytes) and not text:
            raise ConfigError(
                f"dhcpd defines option {int(key)} with a structure of its own, so "
                "it cannot be given as octets; pass dhcpd's own statement through "
                "the reservation's extras"
            )
        if int(key) not in _OPTIONS:
            # dhcpd knows no name for it: `unknown-<n>` takes quoted text or
            # the option's octets.
            option = f"unknown-{int(key)}"
            if not text:
                raw = bytes(lease.options[int(key)]).hex()
                value = ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))
            parts.append(f"option {option} {_render(option, value, text)};")
            continue
        if issubclass(codec, Bytes) and not text:
            # dhcpd reads octets as colon-separated hex.
            value = ":".join(value[i : i + 2] for i in range(0, len(value), 2))
        elif issubclass(codec, DomainName):
            # dhcpd's domain-name type is a bare name; quoted, it is refused.
            if not _DOMAIN.match(str(value)):
                raise ConfigError(
                    f"dhcpd option {_OPTIONS[int(key)]!r} takes a domain name, not "
                    f"{value!r}"
                )
            parts.append(f"option {_OPTIONS[int(key)]} {value};")
            continue
        elif isinstance(value, bool) and int(key) in _FLAG_AS_NUMBER:
            value = int(value)
        elif isinstance(value, bool):
            value = "true" if value else "false"
        option = _OPTIONS[int(key)]
        parts.append(f"option {option} {_render(option, value, text)};")
    for field, keyword in _STATEMENTS:
        value = getattr(lease, field)
        if field == "siaddr":
            if not value.is_unspecified:
                parts.append(f"{keyword} {_render(keyword, value, False)};")
        elif value:
            parts.append(f"{keyword} {_render(keyword, value, True)};")
    parts.extend(str(line) for line in (extras or []))
    return " ".join(parts)


def _quote_text(text: str) -> str:
    """A dhcpd string literal. The one place `"` and `\\` are escaped."""
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _render(keyword: str, value: Any, text: bool) -> str:
    """One value, quoted (`text`) or bare, never able to end its statement."""
    if isinstance(value, (list, tuple)):
        return ", ".join(_render(keyword, item, text) for item in value)
    rendered = str(value)
    if any(ch in rendered for ch in "\r\n\x00"):
        raise ConfigError(
            f"dhcpd option {keyword!r} value contains a newline or NUL, which "
            "cannot be written into a dhcpd statement: " + repr(rendered)
        )
    if text:
        return _quote_text(rendered)
    if not _BARE.match(rendered):
        raise ConfigError(
            f"dhcpd option {keyword!r} expects an address or number, got "
            f"{rendered!r}; quote it as text by using a text option, or pass it "
            "through the reservation's extras if you know what dhcpd expects"
        )
    return rendered
