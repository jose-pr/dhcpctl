"""Kea backend: `reservation-add` / `reservation-del` through the control agent.

Those commands come from Kea's **host_cmds** hook library, and they need a hosts
backend that is writable: a file-only Kea loads the library and still refuses.
That is a precondition to report clearly, not to work around.

The reservation's `subnet-id` is a property of the network, so it comes from the
reservation's scope -- declared, or found by matching the scope's network against
the server's own config -- never from the connection string.
"""

from __future__ import annotations

import json as _json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from .._conditions import Condition
from .._model import Reservation
from .._server import DEFAULT_OWNER, DHCPServer, Secrets
from ..exceptions import (
    BackendUnavailableError,
    ConditionMissingError,
    ConfigError,
    ReservationExistsError,
    ServerError,
)

__all__ = ["KeaBackend"]

LOGGER = logging.getLogger("dhcpctl")

#: Reservation *fields* in Kea's model: they are not `option-data` entries.
_FIELDS = {
    "next-server": "next-server",
    "boot-file-name": "boot-file-name",
    "host-name": "hostname",
}


class KeaBackend(DHCPServer):
    """`kea://[user@]host:8000/?service=dhcp4` (`keas://` for https).

    Client options ride in the query; `subnet_id` does not -- it belongs to the
    scope, because one Kea serves many subnets. The account is the `user` and
    `password` secrets: the URI's, else the caller's.
    """

    SETTINGS = frozenset({"service"})

    def __init__(
        self, uri: str, *, secrets: Secrets = None, owner: str = DEFAULT_OWNER
    ) -> None:
        super().__init__(uri, secrets=secrets, owner=owner)
        parts = urlsplit(uri)
        scheme = "https" if parts.scheme.lower() == "keas" else "http"
        port = parts.port or 8000
        self.endpoint = f"{scheme}://{parts.hostname or 'localhost'}:{port}/"
        self.service = self.settings.get("service", "dhcp4")
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
                "the Kea backend requires dhcpctl's 'kea' extra: "
                "pip install dhcpctl[kea]"
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
        # Classes before the reservation: a reservation naming a class Kea does
        # not know is accepted and then never matches.
        for condition in reservation.conditions.values():
            self.ensure_condition(reservation, condition)
        entry = self._reservation(reservation)
        result = self.command("reservation-add", {"reservation": entry})
        code = result.get("result")
        if code == 0:
            return
        text = result.get("text", "")
        if code == 1 and "exist" in text.lower():
            raise ReservationExistsError(
                f"kea already holds a reservation for {entry['hw-address']} "
                f"in subnet {entry['subnet-id']}: {text}. Remove it first: "
                f"{self.owner} does not overwrite a reservation it did not make."
            )
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
        result = self.command("reservation-del", arguments)
        code = result.get("result")
        if code in (0, 3):  # 3 = "not found", which is success for cleanup
            return
        raise ServerError(_explain(command="reservation-del", result=result))

    def keep(self, reservation: Reservation) -> None:
        """Rewrite the reservation with the completion options.

        Kea has no partial reservation update, so this is `reservation-add`,
        which upserts: a failure leaves the old reservation in place rather than
        none at all.
        """
        entry = self._reservation(reservation)
        entry.pop("client-classes", None)
        for field in ("boot-file-name", "next-server"):
            entry.pop(field, None)
        option_data = [
            item
            for item in entry.get("option-data", [])
            if item.get("name") not in ("boot-file-name", "tftp-server-name")
        ]
        for name, value in reservation.completion.options.items():
            field = _FIELDS.get(name)
            if field:
                entry[field] = _value(value)
            else:
                option_data.append({"name": name, "data": _value(value)})
        if option_data:
            entry["option-data"] = option_data
        else:
            entry.pop("option-data", None)
        result = self.command(
            "reservation-add",
            {"reservation": entry, "subnet-id": entry.get("subnet-id")},
        )
        if result.get("result") != 0:
            raise ServerError(_explain(command="reservation-add", result=result))

    # -- conditions (client classes) ---------------------------------------

    def ensure_condition(self, reservation: Reservation, condition: Condition) -> str:
        """Use the class if Kea has it, add it if the hook allows, else explain.

        `class-get` needs no hook, so a Kea whose classes are defined by config
        management is armed against without the right to write them.
        """
        existing = self.command("class-get", {"name": condition.name})
        if existing.get("result") == 0:
            return condition.name

        added = self.command("class-add", {"client-classes": [_class(condition)]})
        code = added.get("result")
        if code == 0:
            LOGGER.info("kea: created client class %s", condition.name)
            return condition.name
        if code == 2:  # unsupported command -- the class_cmds hook is not loaded
            raise ConditionMissingError(
                f"kea has no client class {condition.name!r} and the "
                f"`class_cmds` hook is not loaded, so {self.owner} cannot add one. "
                f"Either load that hook or add this to kea-dhcp4.conf:",
                self.condition_recipe(reservation, condition),
            )
        raise ServerError(_explain(command="class-add", result=added))

    def condition_recipe(self, reservation: Reservation, condition: Condition) -> str:
        """The `client-classes` entry for `kea-dhcp4.conf`."""
        return (
            f"// {self.owner}: add to kea-dhcp4.conf under Dhcp4.client-classes\n"
            + _json.dumps(_class(condition), indent=2)
        )

    def remove_condition_member(
        self, reservation: Reservation, condition: Condition
    ) -> None:
        """Rewrite the reservation without its classes, keeping the class itself."""
        entry = self._reservation(reservation)
        entry.pop("client-classes", None)
        self.command(
            "reservation-add",
            {"reservation": entry, "subnet-id": entry.get("subnet-id")},
        )

    # -- building the reservation -----------------------------------------

    def _reservation(self, reservation: Reservation) -> Dict[str, Any]:
        target = reservation.target
        mac = target.require_mac("a Kea reservation is identified by one")

        entry: Dict[str, Any] = {
            "subnet-id": self._subnet_id(reservation),
            "hw-address": str(mac),
        }
        if target.ip:
            entry["ip-address"] = target.ip_text

        option_data: List[Any] = []
        for name, value in reservation.options.items():
            field = _FIELDS.get(name)
            if field:
                entry[field] = _value(value)
                continue
            if name.startswith("option-") or name.isdigit():
                code = name[len("option-") :] if name.startswith("option-") else name
                option_data.append({"code": int(code), "data": _value(value)})
            else:
                option_data.append({"name": name, "data": _value(value)})
        option_data.extend(self.extras(reservation, "add"))
        if option_data:
            entry["option-data"] = option_data
        if reservation.conditions:
            # Kea evaluates the class test per packet; the reservation only says
            # which classes this host may be in.
            entry["client-classes"] = sorted(reservation.conditions)
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
            config = self.command("config-get").get("arguments", {})
            subnets = config.get(f"Dhcp{self.service[-1]}", {}).get("subnet4", [])
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


def _class(condition: Condition) -> Dict[str, Any]:
    """A Kea `client-classes` entry for this condition."""
    tests = [
        f"option[{code}].text == '{_escape_test(value)}'"
        for code, value in condition.option_codes.items()
    ]
    entry: Dict[str, Any] = {
        "name": condition.name,
        "test": " and ".join(tests),
    }
    option_data = []
    for name, value in condition.options.items():
        if name in _FIELDS:
            # Reservation fields are not options; a class has to use the option
            # spelling instead.
            option_data.append({"name": _CLASS_OPTIONS[name], "data": _value(value)})
            continue
        if name.startswith("option-") or name.isdigit():
            code = name[len("option-") :] if name.startswith("option-") else name
            option_data.append({"code": int(code), "data": _value(value)})
        else:
            option_data.append({"name": name, "data": _value(value)})
    if option_data:
        entry["option-data"] = option_data
    return entry


#: A reservation field's option-name equivalent, for a class.
_CLASS_OPTIONS = {
    "boot-file-name": "boot-file-name",
    "next-server": "tftp-server-name",
    "host-name": "host-name",
}


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
    return message
