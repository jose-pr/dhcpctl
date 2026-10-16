"""The contract every backend implements."""

from __future__ import annotations

from typing import Any, Callable, ClassVar, FrozenSet, List, Mapping, Optional, Union
from urllib.parse import unquote, urlsplit

from ._conditions import NAME_CHARS, Condition
from ._model import Reservation
from ._options import PHASES, DHCPOptions, split_query
from .exceptions import ConditionUnsupportedError, ConfigError

__all__ = ["DHCPServer", "Secrets", "DEFAULT_OWNER"]

#: What marks the entries a server writes as its own, unless told otherwise.
DEFAULT_OWNER = "dhcpctl"

#: Where a backend's secrets come from when the URI does not carry them: a
#: mapping, or a function from a key (`user`, `password`, `keyname`,
#: `omapi_key`) to its value or None.
Secrets = Union[Mapping[str, str], Callable[[str], Optional[str]], None]


class DHCPServer:
    """A DHCP server reached through one backend, described by a URI.

    Build one with `dhcpctl.connect(uri)`, which picks the backend by the URI's
    scheme. Constructing a backend validates its URI and does no I/O.

    A backend overrides `add` and `remove`, and `keep`, `ensure_condition`,
    `condition_recipe` and `remove_condition_member` where it supports them.
    `complete` and `extras` are the same for every backend.
    """

    #: Query keys this backend reads as connection settings. Every other key in
    #: the query is a client option; the two sets stay disjoint.
    SETTINGS: ClassVar[FrozenSet[str]] = frozenset()

    #: Which secret the URI's user and password parts supply.
    URI_SECRETS: ClassVar[Mapping[str, str]] = {
        "username": "user",
        "password": "password",
    }

    def __init__(
        self, uri: str, *, secrets: Secrets = None, owner: str = DEFAULT_OWNER
    ) -> None:
        self.uri = uri
        parts = urlsplit(uri)
        #: The URI's scheme, which is also the name `raw.<name>` fragments use.
        self.scheme = parts.scheme.lower()
        self.settings, self.options, self.options_builder = split_query(
            uri, self.SETTINGS, self.scheme
        )
        if not owner or set(owner) - NAME_CHARS:
            raise ConfigError(
                f"owner {owner!r} may only contain letters, digits, '-' and '_'"
            )
        #: Names what this server writes on the DHCP server: the dnsmasq region
        #: markers, Windows policy names, recipe comments. Entries written under
        #: one owner are not found under another.
        self.owner = owner
        self._secrets = secrets
        self._uri_secrets = {
            key: unquote(value)
            for part, key in self.URI_SECRETS.items()
            for value in (getattr(parts, part),)
            if value
        }

    @property
    def redacted_uri(self) -> str:
        """`uri` with any password replaced by `***`: what messages and logs show."""
        parts = urlsplit(self.uri)
        if parts.password is None:
            return self.uri
        userinfo, _, hostport = parts.netloc.rpartition("@")
        user = userinfo.partition(":")[0]
        return parts._replace(netloc=f"{user}:***@{hostport}").geturl()

    def __str__(self) -> str:
        return self.redacted_uri

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.redacted_uri!r})"

    def secret(self, key: str) -> Optional[str]:
        """The secret named `key`: the URI's if it carries it, else the caller's.

        The caller's `secrets` are asked when the value is needed, not at
        construction. None when neither has it.
        """
        if key in self._uri_secrets:
            return self._uri_secrets[key]
        source = self._secrets
        if source is None:
            return None
        if callable(source):
            return source(key)
        return source.get(key)

    def client_options(
        self,
        *layers: "Mapping[str, Any]",
        defaults: "Optional[Mapping[str, Any]]" = None,
    ) -> DHCPOptions:
        """Options to serve, layered: `defaults`, this URI's options, then `layers`.

        Later wins. The URI's `raw.*` fragments are carried along. The result is
        what a `Reservation` takes as its `options`.
        """
        options = DHCPOptions(defaults or {})
        options.update(self.options)
        options.raw.update(self.options.raw)
        for layer in layers:
            options.update(layer)
        return options

    # -- what a backend implements --------------------------------------------

    def add(self, reservation: Reservation) -> None:
        """Arm the server for this reservation."""

    def remove(self, reservation: Reservation) -> None:
        """Remove this reservation; removing one that is not there succeeds."""

    def keep(self, reservation: Reservation) -> None:
        """Keep the entry with `reservation.completion`'s options instead.

        The base refuses, so a backend that cannot keep an entry is reported
        rather than silently ignoring the request.
        """
        raise NotImplementedError(
            f"{type(self).__name__} cannot keep a reservation on completion, so "
            f"completion.keep cannot be honoured on {self}"
        )

    def ensure_condition(self, reservation: Reservation, condition: Condition) -> str:
        """The name of the construct serving `condition`, creating it if needed.

        The ladder every backend walks: (1) it exists -- use it; (2) it is
        absent and can be created -- create it; (3) it cannot be created --
        `ConditionMissingError` carrying `condition_recipe()`; (4) this backend
        has no such concept -- `ConditionUnsupportedError`, the base behaviour.
        """
        raise ConditionUnsupportedError(
            f"{type(self).__name__} cannot serve conditional options, so "
            f"dhcp_when.{condition.name} cannot be applied on {self}"
        )

    def condition_recipe(self, reservation: Reservation, condition: Condition) -> str:
        """What a privileged operator applies for `condition`, as text, not run.

        The same text `ConditionMissingError` carries.
        """
        return ""

    def remove_condition_member(
        self, reservation: Reservation, condition: Condition
    ) -> None:
        """Detach this client from `condition`, leaving the construct for others."""

    # -- shared behaviour ------------------------------------------------------

    def complete(self, reservation: Reservation) -> None:
        """Disarm, honouring `reservation.completion`.

        `remove` unless the entry is kept; when it is, the client first leaves
        every condition (a kept entry still matching one would keep being served
        the installer) and then `keep` replaces its boot options.
        """
        if not reservation.completion.keep:
            return self.remove(reservation)
        for condition in reservation.conditions.values():
            self.remove_condition_member(reservation, condition)
        return self.keep(reservation)

    def extras(self, reservation: Reservation, phase: str = "add") -> List[Any]:
        """Backend-native fragments to apply with the reservation, verbatim.

        The URI's `raw.<scheme>` fragments for `phase`, then the reservation's
        own `extras[phase]`. A subclass may override this to decide fragments
        per client (`reservation.context` is the caller's), calling `super()` to
        keep these. What a fragment is belongs to the backend.
        """
        if phase not in PHASES:
            raise ValueError(f"phase must be one of {PHASES}, not {phase!r}")
        lines = self.options.raw_for(self.scheme, phase)
        return lines + list(reservation.extras.get(phase, ()))
