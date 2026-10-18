"""The contract every backend implements."""

from __future__ import annotations

import contextlib as _contextlib

from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Union,
)
from urllib.parse import parse_qsl, unquote, urlsplit

from ._conditions import NAME_CHARS, Condition
from ._model import Reservation
from ._options import (
    PHASES,
    PYDHCP_CODES,
    OptionCodes,
    option_codes,
)
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

    #: The query keys this backend reads: how to reach the server, and nothing
    #: else may be in a URI's query.
    SETTINGS: ClassVar[FrozenSet[str]] = frozenset()

    #: The backend's own option spellings (`option_codes` declarations), under
    #: whatever names the caller declares.
    OPTION_NAMES: ClassVar[Mapping[str, Any]] = {}

    #: Which secret the URI's user and password parts supply.
    URI_SECRETS: ClassVar[Mapping[str, str]] = {
        "username": "user",
        "password": "password",
    }

    def __init__(
        self,
        uri: str,
        *,
        secrets: Secrets = None,
        owner: str = DEFAULT_OWNER,
        codes: Any = None,
    ) -> None:
        self.uri = uri
        base = option_codes(self.OPTION_NAMES) if self.OPTION_NAMES else PYDHCP_CODES
        #: The codemap this server reads option names with: the caller's
        #: declarations over the backend's own spellings over pydhcp's.
        self.codes = OptionCodes.of(codes).over(base)
        parts = urlsplit(uri)
        #: The URI's scheme.
        self.scheme = parts.scheme.lower()
        #: The backend's own query keys: a URI says only how to reach the server.
        self.settings: Dict[str, str] = {}
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if key not in self.SETTINGS:
                raise ConfigError(
                    f"unknown key {key!r} in a {self.scheme} connection: its query "
                    f"takes only how to reach the server "
                    f"({', '.join(sorted(self.SETTINGS)) or 'nothing'}); options "
                    f"belong to the reservation"
                )
            self.settings[key] = value
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
        """The secret named `key`: the caller's if it gives one, else the URI's.

        The caller's `secrets` override the URI's, so one URI serves several
        logins; a caller's None leaves the URI's in place, and `""` is an empty
        secret. They are asked when the value is needed, not at construction.
        None when neither has it.
        """
        source = self._secrets
        given = None
        if callable(source):
            given = source(key)
        elif source is not None:
            given = source.get(key)
        if given is not None:
            return given
        return self._uri_secrets.get(key)

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

    #: What `render` can show: the operations that send something.
    RENDERED = ("add", "remove", "keep", "complete")

    def render(self, reservation: Reservation, action: str = "add") -> str:
        """What `action` would send this server for `reservation`, contacting
        nothing: the backend's own text, one step after another.

        `action` is `add`, `remove`, `keep` or `complete`. A step that needs an
        answer from the server is given the answer "there is nothing yet", so
        the text is what a server holding nothing for this client would get.

        :raises NotImplementedError: the backend cannot record what it sends.
        :raises ValueError: an unknown `action`.
        """
        if action not in self.RENDERED:
            raise ValueError(f"action must be one of {self.RENDERED}, not {action!r}")
        sent: List[str] = []
        with self._recording(sent):
            getattr(self, action)(reservation)
        return "\n".join(sent) + ("\n" if sent else "")

    def _recording(self, sent: List[str]) -> Any:
        """A context in which what this backend sends is appended to `sent`
        instead; a backend that can render overrides it."""
        raise NotImplementedError(
            f"{type(self).__name__} cannot render what it would send"
        )

    @_contextlib.contextmanager
    def _replaced(self, **seams: Any) -> Any:
        """Put `seams` on this instance for the duration, then restore it."""
        missing = object()
        saved = {name: vars(self).get(name, missing) for name in seams}
        vars(self).update(seams)
        try:
            yield
        finally:
            for name, value in saved.items():
                if value is missing:
                    vars(self).pop(name, None)
                else:
                    vars(self)[name] = value

    def extras(self, reservation: Reservation, phase: str = "add") -> List[Any]:
        """Backend-native fragments to apply with the reservation, verbatim.

        `reservation.extras[phase]`. A subclass may override this to decide
        fragments per client (`reservation.context` is the caller's), calling
        `super()` to keep these. What a fragment is belongs to the backend.
        """
        if phase not in PHASES:
            raise ValueError(f"phase must be one of {PHASES}, not {phase!r}")
        return list(reservation.extras.get(phase, ()))
