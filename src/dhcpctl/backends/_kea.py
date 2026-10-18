"""Kea backend: `reservation-add` / `reservation-del` through the control agent.

Those commands come from Kea's **host_cmds** hook library, and they need a hosts
backend that is writable, or `target=memory` to keep reservations in Kea's
running configuration: a Kea with neither loads the library and still refuses.

The reservation's `subnet-id` is a property of the network, so it comes from the
reservation's scope -- declared, or found by matching the scope's network against
the server's own config -- never from the connection string.

A condition is a client class of this client's own, its test the condition's
and the client's MAC. Kea serves a reservation's values over any class's, so a
value a condition overrides is not in the reservation: it is in a second class
of the client's, which matches when none of its conditions does. A
reservation's own `client-classes` would put the client in a class whatever
the class's test says, so a reservation names none.
"""

from __future__ import annotations

import json as _json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from pydhcp.options import Bytes, DomainList, OctetString, String

from .._conditions import Condition
from .._model import Reservation
from .._options import UNSPECIFIED, DHCPLease, DHCPOptionCode, plain_items
from .._server import DEFAULT_OWNER, DHCPServer, Secrets
from ..exceptions import (
    BackendUnavailableError,
    ConditionMissingError,
    ConfigError,
    ServerError,
)

__all__ = ["KeaBackend"]

LOGGER = logging.getLogger("dhcpctl")

#: Options that are reservation *fields* in Kea's model, not `option-data`.
_FIELDS = {DHCPOptionCode.HOSTNAME: "hostname"}

#: The lease's BOOTP header fields, by Kea's names for them (a reservation and
#: a client class take all three).
_BOOT_FIELDS = (
    ("siaddr", "next-server"),
    ("sname", "server-hostname"),
    ("file", "boot-file-name"),
)


class KeaBackend(DHCPServer):
    """`kea://[user@]host:8000/?service=dhcp4&target=` (`keas://` for https).

    The subnet id belongs to the reservation's scope, because one Kea serves
    many subnets. The account is the `user` and
    `password` secrets: the URI's, else the caller's. `target=` is host_cmds'
    `operation-target`: `memory` keeps reservations in Kea's running
    configuration, which a Kea with no hosts database needs; `database`, `all`
    and `default` as Kea defines them (Kea 2.7.4 or later).
    """

    SETTINGS = frozenset({"service", "target"})
    #: Kea's names for the options and header fields its users name most; Kea
    #: is sent codes.
    OPTION_NAMES = {
        "routers": "router",
        "domain-name-servers": "dns",
        "boot-file-name": "file",
        "server-hostname": "sname",
        "tftp-server-name": "tftp-server",
        "host-name": "hostname",
        "dhcp-lease-time": "ip-address-lease-time",
    }

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
        scheme = "https" if parts.scheme.lower() == "keas" else "http"
        port = parts.port or 8000
        self.endpoint = f"{scheme}://{parts.hostname or 'localhost'}:{port}/"
        self.service = self.settings.get("service", "dhcp4")
        if self.service != "dhcp4":
            # A reservation here is DHCPv4: subnet4, hw-address, option codes.
            raise ConfigError(
                f"kea: service={self.service!r} is not supported; reservations are "
                f"made for dhcp4 only"
            )
        self.target = self.settings.get("target")
        if self.target is not None and self.target not in _TARGETS:
            raise ConfigError(
                f"kea: target must be one of {', '.join(_TARGETS)}, not "
                f"{self.target!r}"
            )
        self._subnet_ids: Dict[str, int] = {}

    @property
    def auth(self) -> "Optional[tuple]":
        user = self.secret("user")
        if not user:
            return None
        return (user, self.secret("password") or "")

    # -- transport --------------------------------------------------------

    def command(self, command: str, arguments: "Optional[dict]" = None) -> dict:
        """Send one command and return its (single) response object."""
        try:
            import requests
        except ImportError as exc:  # pragma: no cover - only without the extra
            raise BackendUnavailableError(
                "the Kea backend requires the 'kea' extra: "
                "pip install pydhcpctl[kea]"
            ) from exc

        payload: Dict[str, Any] = {"command": command, "service": [self.service]}
        if arguments is not None:
            payload["arguments"] = arguments
        LOGGER.debug("kea %s -> %s", command, self.endpoint)
        try:
            response = requests.post(
                self.endpoint, json=payload, auth=self.auth, timeout=30
            )
            response.raise_for_status()
            body = response.json()
        except requests.RequestException as exc:
            raise ServerError(
                f"kea {command} to {self.endpoint} failed: {exc}"
            ) from exc
        if not isinstance(body, list) or not body:
            raise ServerError(
                f"kea returned no response object for {command!r}: {body!r}"
            )
        return body[0]

    # -- the DHCPServer contract ------------------------------------------

    def add(self, reservation: Reservation) -> None:
        # Classes before the reservation, so a client is never served the
        # reservation without the classes that complete it.
        for condition in reservation.conditions.values():
            self.ensure_condition(reservation, condition)
        base = _base_class(reservation, self.owner)
        if base is not None:
            self._put_class(base, reservation, None)
        entry = self._reservation(reservation)
        result = self.command("reservation-add", self._hosts({"reservation": entry}))
        code = result.get("result")
        if code == 0:
            return
        text = result.get("text", "").lower()
        if code == 1 and ("exist" in text or "already" in text):
            # Re-arming replaces the reservation Kea holds for this client
            # (Kea 3 says it "has already been added").
            self._replace(entry)
            return
        raise ServerError(_explain(command="reservation-add", result=result))

    def remove(self, reservation: Reservation) -> None:
        target = reservation.target
        arguments = {
            "subnet-id": self._subnet_id(reservation),
            "identifier-type": "hw-address",
            "identifier": str(
                target.require_mac("a Kea reservation is identified by one")
            ),
        }
        result = self.command("reservation-del", self._hosts(arguments))
        code = result.get("result")
        if code not in (0, 3):  # 3 = "not found", which is success for cleanup
            raise ServerError(_explain(command="reservation-del", result=result))
        for condition in reservation.conditions.values():
            self.remove_condition_member(reservation, condition)

    def keep(self, reservation: Reservation) -> None:
        """Rewrite the reservation with the completion's lease applied, and the
        `remove`-phase extras, as every backend's keep does: all of it in the
        reservation, as a kept client is in no condition."""
        entry = self._reservation(
            reservation,
            reservation.completion.apply_to(reservation.lease),
            phase="remove",
            conditional=False,
        )
        self._replace(entry)

    def _replace(self, entry: Dict[str, Any]) -> None:
        """Write `entry` over the reservation Kea already holds for its MAC.

        `reservation-add` refuses an existing reservation, so this is
        `reservation-update`; a Kea without that command (result 2) gets the
        reservation deleted and added again. Every result is checked.
        """
        updated = self.command(
            "reservation-update", self._hosts({"reservation": entry})
        )
        code = updated.get("result")
        if code == 0:
            return
        if code != 2:
            raise ServerError(_explain(command="reservation-update", result=updated))
        deleted = self.command(
            "reservation-del",
            self._hosts(
                {
                    "subnet-id": entry["subnet-id"],
                    "identifier-type": "hw-address",
                    "identifier": entry["hw-address"],
                }
            ),
        )
        if deleted.get("result") not in (0, 3):
            raise ServerError(_explain(command="reservation-del", result=deleted))
        added = self.command("reservation-add", self._hosts({"reservation": entry}))
        if added.get("result") != 0:
            raise ServerError(_explain(command="reservation-add", result=added))

    def _recording(self, sent: List[str]) -> Any:
        """Each command as the JSON body Kea would be posted; Kea holds no class."""

        def command(name: str, arguments: "Optional[dict]" = None) -> dict:
            if name == "config-get":
                raise ConfigError(
                    "kea: rendering asks Kea nothing, so give the reservation's "
                    "scope its subnet id"
                )
            if name == "class-get":
                return {"result": 3}
            body: Dict[str, Any] = {"command": name, "service": [self.service]}
            if arguments is not None:
                body["arguments"] = arguments
            sent.append(_json.dumps(body, indent=2))
            return {"result": 0}

        return self._replaced(command=command)

    def _hosts(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """A host_cmds command's arguments, with `target=` as its operation-target."""
        if self.target is not None:
            arguments = dict(arguments, **{"operation-target": self.target})
        return arguments

    # -- conditions (client classes) ---------------------------------------

    def ensure_condition(self, reservation: Reservation, condition: Condition) -> str:
        """Put this client's class for `condition` in place, adding or updating it.

        The class is the client's own, so its values are this reservation's;
        without the `class_cmds` hook it cannot be written, and the error hands
        over the class to add to `kea-dhcp4.conf`.
        """
        entry = _class(condition, reservation)
        self._put_class(entry, reservation, condition)
        return entry["name"]

    def _put_class(
        self,
        entry: Dict[str, Any],
        reservation: Reservation,
        condition: "Optional[Condition]",
    ) -> None:
        """`class-update` the class Kea holds by this name, else `class-add` it."""
        existing = self.command("class-get", {"name": entry["name"]})
        command = "class-update" if existing.get("result") == 0 else "class-add"
        result = self.command(command, {"client-classes": [entry]})
        code = result.get("result")
        if code == 0:
            LOGGER.info("kea: %s client class %s", command[6:] + "d", entry["name"])
            return
        if code == 2:  # unsupported command -- the class_cmds hook is not loaded
            recipe = (
                self.condition_recipe(reservation, condition)
                if condition is not None
                else _recipe(self.owner, [entry])
            )
            raise ConditionMissingError(
                f"kea has no client class {entry['name']!r} and the `class_cmds` "
                f"hook is not loaded, so {self.owner} cannot add one. Either load "
                "that hook or add this to kea-dhcp4.conf:",
                recipe,
            )
        raise ServerError(_explain(command=command, result=result))

    def condition_recipe(self, reservation: Reservation, condition: Condition) -> str:
        """This client's `client-classes` entries for `kea-dhcp4.conf`: the
        condition's, then the one serving what it overrides when it does not
        match."""
        entries = [_class(condition, reservation)]
        base = _base_class(reservation, self.owner)
        if base is not None:
            entries.append(base)
        return _recipe(self.owner, entries)

    def remove_condition_member(
        self, reservation: Reservation, condition: Condition
    ) -> None:
        """Delete this client's class for `condition`, and the class serving what
        its conditions override; a class already gone is fine."""
        # The base class names the condition's in its test, so it goes first.
        names = [
            _base_name(reservation, self.owner),
            _class(condition, reservation)["name"],
        ]
        for name in names:
            result = self.command("class-del", {"name": name})
            if result.get("result") not in (0, 2, 3):
                raise ServerError(_explain(command="class-del", result=result))

    # -- building the reservation -----------------------------------------

    def _reservation(
        self,
        reservation: Reservation,
        lease: "Optional[DHCPLease]" = None,
        phase: str = "add",
        conditional: bool = True,
    ) -> Dict[str, Any]:
        """The reservation entry serving `lease` (the reservation's own), with
        `phase`'s extras; `conditional`, without what its conditions override."""
        lease = lease or reservation.lease
        if conditional:
            lease = _without(lease, _overridden(reservation))
        mac = reservation.target.require_mac("a Kea reservation is identified by one")

        entry: Dict[str, Any] = {
            "subnet-id": self._subnet_id(reservation),
            "hw-address": str(mac),
        }
        if reservation.ip_text:
            entry["ip-address"] = reservation.ip_text

        option_data: List[Any] = []
        for key, value in plain_items(lease.options):
            field = _FIELDS.get(key)
            if field:
                entry[field] = _value(value)
            else:
                option_data.append(_option_data(key, value))
        entry.update(_boot_fields(lease))
        option_data.extend(self.extras(reservation, phase))
        if option_data:
            entry["option-data"] = option_data
        return entry

    def _subnet_id(self, reservation: Reservation) -> int:
        """The scope's subnet id: declared, else found once by `config-get`.

        Never a guess: a reservation in the wrong subnet silently never matches.
        """
        scope = reservation.scope
        if scope.subnet_id is not None:
            return int(scope.subnet_id)
        key = scope.name or str(scope.network or "")
        if key in self._subnet_ids:
            return self._subnet_ids[key]

        network = scope.network
        if network is not None:
            config = self.command("config-get").get("arguments", {}).get("Dhcp4", {})
            # A subnet is at the top level or inside a shared network.
            subnets = list(config.get("subnet4", []))
            for shared in config.get("shared-networks", []):
                subnets.extend(shared.get("subnet4", []))
            for subnet in subnets:
                if str(subnet.get("subnet", "")) == str(network):
                    found = int(subnet["id"])
                    self._subnet_ids[key] = found
                    LOGGER.debug("kea subnet-id %s for scope %s", found, key)
                    return found

        raise ConfigError(
            f"kea: no subnet-id for scope {scope.name!r} (network {network!r}). "
            "Give the scope a subnet_id, or add a matching subnet4 entry to Kea "
            "-- a reservation in the wrong subnet never matches."
        )


def _client(reservation: Reservation) -> str:
    """The client's MAC as Kea's `pkt4.mac` compares it: `0x` and its octets."""
    mac = reservation.target.require_mac("a Kea reservation is identified by one")
    return "0x" + mac.hex()


def _class(condition: Condition, reservation: Reservation) -> Dict[str, Any]:
    """This client's `client-classes` entry for `condition`.

    `.hex` compares the option's octets with the text: iPXE sends option 77 as
    the flat string `iPXE`, which `.text` of an RFC 3004 user class is not.
    """
    tests = [
        f"option[{code}].hex == '{_escape_test(value)}'"
        for code, value in condition.option_codes.items()
    ]
    entry: Dict[str, Any] = {
        "name": f"{condition.name}-{_client(reservation)[2:]}",
        "test": f"pkt4.mac == {_client(reservation)} and " + " and ".join(tests),
    }
    entry.update(_values(condition.lease))
    return entry


def _base_name(reservation: Reservation, owner: str) -> str:
    return f"{owner}-{_client(reservation)[2:]}"


def _base_class(reservation: Reservation, owner: str) -> "Optional[Dict[str, Any]]":
    """The class serving the reservation's own values that its conditions
    override, when none of them matches; None when they override nothing set."""
    overridden = _overridden(reservation)
    values = _values(_only(reservation.lease, overridden))
    if not values:
        return None
    others = " and ".join(
        f"not member('{_class(c, reservation)['name']}')"
        for c in reservation.conditions.values()
    )
    entry: Dict[str, Any] = {
        "name": _base_name(reservation, owner),
        "test": f"pkt4.mac == {_client(reservation)} and {others}",
    }
    entry.update(values)
    return entry


def _values(lease: DHCPLease) -> Dict[str, Any]:
    """What a class serves for `lease`: its options and its header fields."""
    entry: Dict[str, Any] = {}
    option_data = [
        _option_data(key, value) for key, value in plain_items(lease.options)
    ]
    if option_data:
        entry["option-data"] = option_data
    entry.update(_boot_fields(lease))
    return entry


def _overridden(reservation: Reservation) -> "set[str]":
    """The option codes and header fields any of the conditions sets."""
    keys: "set[str]" = set()
    for condition in reservation.conditions.values():
        keys.update(str(int(code)) for code in condition.lease.options)
        keys.update(
            attribute
            for attribute, _ in _BOOT_FIELDS
            if _is_set(getattr(condition.lease, attribute), attribute)
        )
    return keys


def _without(lease: DHCPLease, keys: "set[str]") -> DHCPLease:
    """`lease` with none of `keys` (option codes, header field names)."""
    options = lease.options.copy()
    for code in list(options):
        if str(int(code)) in keys:
            del options[code]
    changes: Dict[str, Any] = {"options": options}
    for attribute, _ in _BOOT_FIELDS:
        if attribute in keys:
            changes[attribute] = UNSPECIFIED if attribute == "siaddr" else ""
    return lease.replace(**changes)


def _only(lease: DHCPLease, keys: "set[str]") -> DHCPLease:
    """`lease` with only `keys` (option codes, header field names)."""
    kept = {str(int(code)) for code in lease.options} - keys
    every = {attribute for attribute, _ in _BOOT_FIELDS}
    return _without(lease, kept | (every - keys))


def _is_set(value: Any, attribute: str) -> bool:
    return bool(value) and not (attribute == "siaddr" and value.is_unspecified)


def _recipe(owner: str, entries: List[Dict[str, Any]]) -> str:
    return (
        f"// {owner}: add to kea-dhcp4.conf under Dhcp4.client-classes\n"
        + "\n".join(_json.dumps(entry, indent=2) for entry in entries)
    )


def _boot_fields(lease: DHCPLease) -> Dict[str, str]:
    """The lease's header fields that are set, by Kea's names."""
    return {
        name: str(getattr(lease, attribute))
        for attribute, name in _BOOT_FIELDS
        if _is_set(getattr(lease, attribute), attribute)
    }


def _option_data(key: Any, value: Any) -> Dict[str, Any]:
    """One `option-data` entry. By code: Kea's names are not pydhcp's.

    Octets go as hex with `csv-format` off, which Kea takes for any option,
    one it has no definition for included; a flag as `true`/`false`.
    """
    codec = key.get_type()
    if issubclass(codec, Bytes) and not issubclass(
        codec, (String, OctetString, DomainList)
    ):
        return {"code": int(key), "csv-format": False, "data": str(value)}
    if isinstance(value, bool):
        return {"code": int(key), "data": "true" if value else "false"}
    return {"code": int(key), "data": _value(value)}


def _escape_test(value: Any) -> str:
    """A value inside a Kea test expression's single quotes."""
    text = str(value)
    if "'" in text or any(ch in text for ch in "\r\n\x00"):
        raise ConfigError(
            f"a kea client class test cannot contain a quote or newline: {text!r}"
        )
    return text


def _value(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return str(value)


#: host_cmds' operation targets.
_TARGETS = ("memory", "database", "all", "default")


def _explain(command: str, result: dict) -> str:
    """A Kea error, plus the cause an operator most often actually has."""
    text = result.get("text", "")
    message = f"kea refused {command}: {text or result!r}"
    if result.get("result") == 2:
        message += (
            " (result 2 is 'unsupported': the host_cmds hook library is probably "
            "not loaded, or the hosts backend is file-only or read-only, which "
            "cannot take live reservations)"
        )
    if "database not available" in text.lower():
        message += (
            " (this Kea has no hosts database: give the URI target=memory to keep "
            "reservations in its running configuration)"
        )
    return message
