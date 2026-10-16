"""The errors dhcpctl raises. Every one derives from `DHCPCtlError`."""

from __future__ import annotations

__all__ = [
    "DHCPCtlError",
    "ConfigError",
    "UnknownBackendError",
    "BackendUnavailableError",
    "MissingMACError",
    "ServerError",
    "ReservationExistsError",
    "ConditionUnsupportedError",
    "ConditionMissingError",
]


class DHCPCtlError(Exception):
    """Base class of every error dhcpctl raises."""


class ConfigError(DHCPCtlError, ValueError):
    """A connection URI, a setting or a value cannot be used as given."""


class UnknownBackendError(ConfigError):
    """No backend is registered for a URI's scheme."""


class BackendUnavailableError(DHCPCtlError, ImportError):
    """A backend needs a library that is not installed; the message names the extra."""


class MissingMACError(DHCPCtlError, LookupError):
    """The target has no MAC address, and the server identifies a reservation by one."""


class ServerError(DHCPCtlError):
    """The server, or the program that talks to it, refused or failed."""


class ReservationExistsError(ServerError):
    """The server already holds a reservation for this client."""


class ConditionUnsupportedError(DHCPCtlError):
    """This backend cannot express a condition at all, so nothing is armed with it."""


class ConditionMissingError(DHCPCtlError):
    """The condition's construct is absent and this backend cannot create it.

    `recipe` is the text a privileged operator applies once, in the server's own
    syntax; it is also appended to the message.
    """

    def __init__(self, message: str, recipe: str = "") -> None:
        super().__init__(message if not recipe else f"{message}\n\n{recipe}")
        self.recipe = recipe
