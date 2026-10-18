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
from .._options import DHCPLease, DHCPOptionCode, plain_items
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
    """`kea://[user@]host:8000/?service=dhcp4` (`keas://` for https).

    The subnet id belongs to the reservation's scope, because one Kea serves
    many subnets. The account is the `user` and
    `password` secrets: the URI's, else the caller's.
    """

    SETTINGS = frozenset({"service"})
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
        """Rewrite the reservation with the completion's lease applied, and the
        `remove`-phase extras, as every backend's keep does."""
        entry = self._reservation(
            reservation,
            reservation.completion.apply_to(reservation.lease),
            phase="remove",
        )
        entry.pop("client-classes", None)
        self._replace(entry)

    def _replace(self, entry: Dict[str, Any]) -> None:
        """Write `entry` over the reservation Kea already holds for its MAC.

        `reservation-add` refuses an existing reservation, so this is
        `reservation-update`; a Kea without that command (result 2) gets the
        reservation deleted and added again. Every result is checked.
        """
        updated = self.command("reservation-update", {"reservation": entry})
        code = updated.get("result")
        if code == 0:
            return
        if code != 2:
            raise ServerError(_explain(command="reservation-update", result=updated))
        deleted = self.command(
            "reservation-del",
            {
                "subnet-id": entry["subnet-id"],
                "identifier-type": "hw-address",
                "identifier": entry["hw-address"],
            },
        )
        if deleted.get("result") not in (0, 3):
            raise ServerError(_explain(command="reservation-del", result=deleted))
        added = self.command("reservation-add", {"reservation": entry})
        if added.get("result") != 0:
            raise ServerError(_explain(command="reservation-add", result=added))

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
        self._replace(entry)

    # -- building the reservation -----------------------------------------

    def _reservation(
        self,
        reservation: Reservation,
        lease: "Optional[DHCPLease]" = None,
        phase: str = "add",
    ) -> Dict[str, Any]:
        """The reservation entry serving `lease` (the reservation's own), with
        `phase`'s extras."""
        lease = lease or reservation.lease
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
    option_data = [
        _option_data(key, value) for key, value in plain_items(condition.lease.options)
    ]
    if option_data:
        entry["option-data"] = option_data
    entry.update(_boot_fields(condition.lease))
    return entry


def _boot_fields(lease: DHCPLease) -> Dict[str, str]:
    """The lease's header fields that are set, by Kea's names."""
    fields = {}
    for attribute, name in _BOOT_FIELDS:
        value = getattr(lease, attribute)
        if value and not (attribute == "siaddr" and value.is_unspecified):
            fields[name] = str(value)
    return fields


def _option_data(key: Any, value: Any) -> Dict[str, Any]:
    """One `option-data` entry. By code: Kea's names are not pydhcp's."""
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
