"""Choosing a backend by URI scheme, and what every backend is built with.

A scheme maps to a class or to a `"module:Class"` name imported on first use,
so naming no `kea://` never needs `requests`. Third-party backends arrive by
`register_backend` or the `dhcpctl.backends` entry-point group.
"""

import importlib.metadata
import logging
import subprocess
import sys
import types

import pytest

import dhcpctl
from dhcpctl import DHCPServer, _registry
from dhcpctl.backends import DHCPDBackend, DnsmasqBackend, KeaBackend, WinDHCPBackend


class _Memory(DHCPServer):
    """A backend that talks to nothing."""


class _Other(DHCPServer):
    """A second backend, to contend for a scheme."""


@pytest.fixture
def fake_module(monkeypatch):
    """An importable module `dhcpctl_test_backends` holding `Memory`."""
    module = types.ModuleType("dhcpctl_test_backends")
    module.Memory = _Memory
    monkeypatch.setitem(sys.modules, "dhcpctl_test_backends", module)
    return module


# -- connect -----------------------------------------------------------------


@pytest.mark.parametrize(
    "uri, backend",
    [
        ("dnsmasq:///?hostsfile=/srv/dnsmasq/hosts.d/", DnsmasqBackend),
        ("kea://kea01:8000/", KeaBackend),
        ("keas://kea01:8443/", KeaBackend),
        ("dhcpd://dhcp01:7911/", DHCPDBackend),
        ("windhcp://admin@dhcp01/", WinDHCPBackend),
    ],
)
def test_connect_picks_each_shipped_backend_by_scheme(uri, backend):
    server = dhcpctl.connect(uri)
    assert type(server) is backend
    assert server.uri == uri
    assert server.scheme == uri.split(":")[0]
    assert server.owner == dhcpctl.DEFAULT_OWNER == "dhcpctl"


def test_the_scheme_is_case_insensitive():
    assert isinstance(dhcpctl.connect("KEA://kea01/"), KeaBackend)


def test_importing_dhcpctl_pulls_in_no_backend_or_its_dependency():
    # The whole point of resolving a backend lazily: a caller that names no
    # kea:// must not need requests. Checked in a fresh interpreter, because
    # other tests in this suite import those modules for their own reasons and
    # this process's sys.modules proves nothing.
    probe = (
        "import sys, dhcpctl, dhcpctl.backends;"
        "names=('requests','pypureomapi','winrm','paramiko','sftppath',"
        "'dhcpctl.backends._dnsmasq','dhcpctl.backends._kea',"
        "'dhcpctl.backends._dhcpd','dhcpctl.backends._windhcp');"
        "print(','.join(m for m in names if m in sys.modules))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "", f"import dhcpctl loaded {result.stdout.strip()}"


def test_connecting_a_backend_imports_only_that_backend():
    probe = (
        "import sys, dhcpctl;"
        "dhcpctl.connect('kea://kea01/');"
        "names=('requests','pypureomapi','winrm','dhcpctl.backends._dhcpd',"
        "'dhcpctl.backends._windhcp','dhcpctl.backends._dnsmasq');"
        "print(','.join(m for m in names if m in sys.modules))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    # Not even requests: it is imported when the first command is sent.
    assert result.stdout.strip() == ""


def test_an_unknown_scheme_says_how_to_provide_one():
    with pytest.raises(dhcpctl.UnknownBackendError) as excinfo:
        dhcpctl.connect("nosuchscheme://host")
    assert isinstance(excinfo.value, dhcpctl.ConfigError)
    assert isinstance(excinfo.value, ValueError)
    message = str(excinfo.value)
    assert "nosuchscheme" in message
    assert "register_backend" in message and "dhcpctl.backends" in message


def test_a_uri_without_a_scheme_is_refused():
    with pytest.raises(dhcpctl.ConfigError, match="no scheme"):
        dhcpctl.connect("//kea01:8000/")
    with pytest.raises(dhcpctl.ConfigError, match="no scheme"):
        dhcpctl.connect("/srv/dnsmasq/hosts.d/")


@pytest.mark.parametrize("owner", ["bad owner", "", "a/b", "it's"])
def test_an_owner_that_cannot_name_an_entry_is_refused(owner):
    with pytest.raises(dhcpctl.ConfigError, match="owner"):
        dhcpctl.connect("kea://kea01/", owner=owner)


def test_a_custom_owner_is_kept():
    assert dhcpctl.connect("kea://kea01/", owner="netboot").owner == "netboot"


# -- the registry ------------------------------------------------------------


def test_register_a_class():
    dhcpctl.register_backend("memory", _Memory)
    server = dhcpctl.connect("memory://host/path")
    assert type(server) is _Memory
    assert server.uri == "memory://host/path"
    assert dhcpctl.get_backend("memory") is _Memory


def test_register_a_name_imported_on_first_use(fake_module):
    dhcpctl.register_backend("memory", "dhcpctl_test_backends:Memory")
    assert _registry._REGISTRY["memory"] == "dhcpctl_test_backends:Memory"
    assert type(dhcpctl.connect("memory://host/")) is _Memory
    # Resolved once, then held as the class.
    assert _registry._REGISTRY["memory"] is _Memory


def test_a_registered_scheme_is_lower_cased():
    dhcpctl.register_backend("MEMORY", _Memory)
    assert "memory" in dhcpctl.backend_names()
    assert type(dhcpctl.connect("memory://host/")) is _Memory


def test_registering_the_same_backend_again_is_harmless():
    dhcpctl.register_backend("memory", _Memory)
    dhcpctl.register_backend("memory", _Memory)
    assert dhcpctl.get_backend("memory") is _Memory


def test_a_taken_scheme_needs_replace():
    dhcpctl.register_backend("memory", _Memory)
    with pytest.raises(ValueError, match="replace=True") as excinfo:
        dhcpctl.register_backend("memory", _Other)
    assert "_Memory" in str(excinfo.value) and "_Other" in str(excinfo.value)
    assert dhcpctl.get_backend("memory") is _Memory

    dhcpctl.register_backend("memory", _Other, replace=True)
    assert dhcpctl.get_backend("memory") is _Other


def test_a_shipped_scheme_can_be_replaced():
    with pytest.raises(ValueError):
        dhcpctl.register_backend("kea", _Memory)
    dhcpctl.register_backend("kea", _Memory, replace=True)
    assert type(dhcpctl.connect("kea://kea01/")) is _Memory


def test_unregister_says_whether_there_was_anything():
    dhcpctl.register_backend("memory", _Memory)
    assert dhcpctl.unregister_backend("MEMORY") is True
    assert dhcpctl.unregister_backend("memory") is False
    with pytest.raises(dhcpctl.UnknownBackendError):
        dhcpctl.connect("memory://host/")


def test_backend_names_are_sorted_and_include_the_shipped_ones():
    dhcpctl.register_backend("aaa", _Memory)
    names = dhcpctl.backend_names()
    assert names == tuple(sorted(names))
    assert {"aaa", "dnsmasq", "kea", "keas", "dhcpd", "windhcp"} <= set(names)


# -- entry points ------------------------------------------------------------


@pytest.fixture
def entry_points(monkeypatch):
    """Serve `found` as the installed `dhcpctl.backends` entry points."""
    found = []

    def fake(group=None, **kwargs):
        assert group == dhcpctl.ENTRY_POINT_GROUP
        return list(found)

    monkeypatch.setattr(importlib.metadata, "entry_points", fake)
    monkeypatch.setattr(_registry, "_ENTRY_POINTS_LOADED", False)
    return found


def _entry(name, value):
    return types.SimpleNamespace(name=name, value=value)


def test_an_entry_point_backend_is_picked_up(entry_points, fake_module):
    entry_points.append(_entry("Memory", "dhcpctl_test_backends:Memory"))
    assert type(dhcpctl.connect("memory://host/")) is _Memory
    assert "memory" in dhcpctl.backend_names()


def test_an_entry_point_cannot_take_a_registered_scheme(entry_points, caplog):
    entry_points.append(_entry("kea", "dhcpctl_test_backends:Memory"))
    with caplog.at_level(logging.WARNING, logger="dhcpctl"):
        names = dhcpctl.backend_names()
    assert "kea" in names
    assert type(dhcpctl.connect("kea://kea01/")) is KeaBackend
    assert "ignored" in caplog.text and "kea" in caplog.text


def test_entry_points_are_read_once(entry_points, fake_module):
    dhcpctl.backend_names()
    # Installed after the first look: not seen until the process restarts.
    entry_points.append(_entry("memory", "dhcpctl_test_backends:Memory"))
    with pytest.raises(dhcpctl.UnknownBackendError):
        dhcpctl.connect("memory://host/")


# -- what every backend is built with ----------------------------------------


def test_a_secret_from_a_mapping():
    server = dhcpctl.connect("kea://kea01/", secrets={"password": "pw"})
    assert server.secret("password") == "pw"
    assert server.secret("user") is None


def test_a_secret_from_a_callable_is_asked_for_when_needed():
    asked = []

    def lookup(key):
        asked.append(key)
        return "pw" if key == "password" else None

    server = dhcpctl.connect("kea://kea01/", secrets=lookup)
    assert asked == [], "nothing is asked for until a backend needs it"
    assert server.secret("password") == "pw"
    assert server.secret("user") is None
    assert asked == ["password", "user"]


def test_no_secrets_means_none():
    assert dhcpctl.connect("kea://kea01/").secret("password") is None


def test_client_options_layer_defaults_then_the_uri_then_the_layers():
    server = dhcpctl.connect("kea://kea01/?router=10.0.0.7&raw.kea=x")
    defaults = {"router": "10.0.0.1", "domain-name": "example.com"}

    options = server.client_options(defaults=defaults)
    assert options == {"router": "10.0.0.7", "domain-name": "example.com"}

    options = server.client_options(
        {"router": "10.0.0.8", "ntp-servers": "10.0.0.123"},
        {"router": "10.0.0.9"},
        defaults=defaults,
    )
    assert options["router"] == "10.0.0.9"
    assert options["ntp-servers"] == "10.0.0.123"
    assert options["domain-name"] == "example.com"
    # The URI's raw fragments are carried, and the result is what a
    # Reservation takes.
    assert isinstance(options, dhcpctl.DHCPOptions)
    assert options.raw_for("kea") == ["x"]
    # The server's own options are not changed by layering.
    assert server.options == {"router": "10.0.0.7"}


def test_the_options_builder_is_stored_not_called():
    server = dhcpctl.connect("kea://kea01/?options_builder=site.dhcp:build")
    assert server.options_builder == "site.dhcp:build"
    assert "options_builder" not in server.client_options()


def test_extras_rejects_an_unknown_phase(reservation):
    server = dhcpctl.connect("kea://kea01/")
    with pytest.raises(ValueError, match="phase must be one of"):
        server.extras(reservation(), "bootstrap")


def test_a_server_names_its_class_and_uri():
    assert repr(dhcpctl.connect("dhcpd://dhcp01/")) == "DHCPDBackend('dhcpd://dhcp01/')"
