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
from pydhcp.options import Bytes

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


# -- a URI says only how to reach the server ----------------------------------

#: Each shipped backend's URI with every one of its settings, and what it reads.
SETTINGS_ONLY = {
    "dnsmasq": (
        "dnsmasq:///?hostsfile=/srv/hosts.d/&optsfile=/srv/opts.d/"
        "&reload=signal&pidfile=/run/dnsmasq.pid",
        {
            "hostsfile": "/srv/hosts.d/",
            "optsfile": "/srv/opts.d/",
            "reload": "signal",
            "pidfile": "/run/dnsmasq.pid",
        },
    ),
    "kea": (
        "kea://kea01/?service=dhcp4&target=memory",
        {"service": "dhcp4", "target": "memory"},
    ),
    "dhcpd": (
        "dhcpd://dhcp01/?keyname=omapi_key&keyfile=/etc/omapi.key&conditions=group",
        {"keyname": "omapi_key", "keyfile": "/etc/omapi.key", "conditions": "group"},
    ),
    "windhcp": (
        "windhcp://admin@dhcp01/?transport=winrm&method=netsh&server=dhcp02"
        "&auth=kerberos&port=5986&ssl=true&conditions=shared&timeout=30",
        {
            "transport": "winrm",
            "method": "netsh",
            "server": "dhcp02",
            "auth": "kerberos",
            "port": "5986",
            "ssl": "true",
            "conditions": "shared",
            "timeout": "30",
        },
    ),
}

#: A misspelling of one of each backend's settings.
TYPOS = {
    "dnsmasq": "hostfile",
    "kea": "servce",
    "dhcpd": "keynme",
    "windhcp": "transprt",
}


@pytest.mark.parametrize("scheme", sorted(SETTINGS_ONLY))
def test_a_uri_with_only_settings_builds(scheme):
    uri, settings = SETTINGS_ONLY[scheme]
    server = dhcpctl.connect(uri)
    assert server.settings == settings
    assert set(settings) == type(server).SETTINGS, "every setting is exercised"


@pytest.mark.parametrize("scheme", sorted(SETTINGS_ONLY))
@pytest.mark.parametrize(
    "key",
    [
        "router",  # pydhcp's option name
        "domain-name-servers",  # Kea's and dhcpd's own spelling of one
        "bootfile-name",
        "option-252",
        "42",
        "options_builder",
        "next-server",
        "raw.dhcpd",
        "typo",
    ],
)
def test_a_key_that_is_no_setting_is_refused(scheme, key):
    uri, settings = SETTINGS_ONLY[scheme]
    key = TYPOS[scheme] if key == "typo" else key
    with pytest.raises(dhcpctl.ConfigError) as excinfo:
        dhcpctl.connect(f"{uri}&{key}=10.0.0.1")
    message = str(excinfo.value)
    assert f"unknown key {key!r} in a {scheme} connection" in message
    assert message.endswith("options belong to the reservation")
    # The refusal says what the query does take.
    assert all(setting in message for setting in settings)


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


def test_a_server_names_its_class_and_uri():
    server = dhcpctl.connect("kea://kea01:8000/?service=dhcp4")
    assert repr(server) == "KeaBackend('kea://kea01:8000/?service=dhcp4')"
    assert str(server) == "kea://kea01:8000/?service=dhcp4"


def test_extras_rejects_an_unknown_phase(reservation):
    server = dhcpctl.connect("kea://kea01/")
    with pytest.raises(ValueError, match="phase must be one of"):
        server.extras(reservation(), "bootstrap")


#: A dnsmasq server that needs nothing installed and touches no file at connect.
DNSMASQ = "dnsmasq:///?hostsfile=/srv/dnsmasq/hosts.d/"


@pytest.mark.parametrize(
    "make", [dict, dhcpctl.option_codes], ids=["mapping", "codemap"]
)
def test_connect_takes_declared_codes_for_the_servers_codemap(make):
    codes = make({"my-option": {"code": 224, "type": "String"}})
    for uri in ("kea://kea01/", DNSMASQ):
        server = dhcpctl.connect(uri, codes=codes)
        options = server.codes.options({"my-option": "y"})
        assert dict(dhcpctl.plain_items(options)) == {224: "y"}
        assert options.get(224) == "y", "the server's codemap decodes it as text"
    # The type is the codemap's: pydhcp's own registry is untouched.
    assert dhcpctl.DHCPOptionCode(224).get_type() is Bytes


def test_without_declared_codes_the_server_cannot_read_them():
    with pytest.raises(dhcpctl.ConfigError, match="unknown option 'my-option'"):
        dhcpctl.connect("kea://kea01/").codes.options({"my-option": "x"})


def test_a_kea_server_reads_keas_spelling_and_dnsmasq_refuses_it():
    kea = dhcpctl.connect("kea://kea01/")
    options = kea.codes.options(
        {"domain-name-servers": "10.0.0.53", "routers": "10.0.0.1"}
    )
    assert dict(dhcpctl.plain_items(options)) == {6: ["10.0.0.53"], 3: ["10.0.0.1"]}

    dnsmasq = dhcpctl.connect(DNSMASQ)
    with pytest.raises(dhcpctl.ConfigError, match="unknown option 'routers'"):
        dnsmasq.codes.options({"routers": "10.0.0.1"})
    with pytest.raises(dhcpctl.ConfigError, match="'domain-name-servers'"):
        dnsmasq.codes.options({"domain-name-servers": "10.0.0.53"})
    # pydhcp's own name is every server's.
    assert dict(dhcpctl.plain_items(dnsmasq.codes.options({"dns": "10.0.0.53"}))) == {
        6: ["10.0.0.53"]
    }


def test_the_callers_codes_stack_over_the_backends():
    server = dhcpctl.connect("kea://kea01/", codes={"routers": 42, "gw": 3})
    # The caller's declaration wins over Kea's `routers` -> router.
    assert int(server.codes.resolve("routers")) == 42
    assert int(server.codes.resolve("gw")) == 3
    # Kea's other spellings and pydhcp's names are still there underneath.
    assert int(server.codes.resolve("tftp-server-name")) == 66
    assert server.codes.field("boot-file-name") == "file"
    assert int(server.codes.resolve("router")) == 3


def test_a_bad_declaration_is_refused_at_connect():
    with pytest.raises(dhcpctl.ConfigError, match="pydhcp's name for option 3"):
        dhcpctl.connect("kea://kea01/", codes={"router": 6})
