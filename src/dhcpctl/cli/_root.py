"""The root parser: the subcommands under one program name."""

from __future__ import annotations

from duho import AUTO, Args

from ..exceptions import ConfigError, DHCPCtlError
from .backends import Backends
from .operations import Add, Complete, Remove
from .recipe import Recipe
from .render import Render


class Dhcpctl(Args):
    """Arm, keep and remove DHCP reservations on dnsmasq, Kea, ISC dhcpd and Windows DHCP."""

    _parsername_ = "dhcpctl"
    _version_ = AUTO
    _distribution_ = "pydhcpctl"
    _subcommands_ = [Render, Add, Complete, Remove, Recipe, Backends]
    # A URI or a reservation that cannot be used is the invocation being wrong;
    # a server that refuses, or cannot be reached, is the operation failing.
    _errors_ = {ConfigError: 2, DHCPCtlError: 1, OSError: 1}
