"""The ISC dhcpd backend, against a stub OMAPI module.

`statements` is a fragment of dhcpd's config language, so most of these tests
are about values that must not be able to end a statement and start another.
"""

import sys
import types

import pytest

import dhcpctl
from dhcpctl import DHCPOptions
from dhcpctl.backends import DHCPDBackend
from dhcpctl.backends._dhcpd import render_statements


class _StubOmapi:
    """Records what the backend would have sent to dhcpd."""

    instances: list = []
    raise_on_delete = None

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.added: list = []
        self.deleted: list = []
        self.closed = False
        _StubOmapi.instances.append(self)

    def add_host_supersede(self, ip, mac, name, **kwargs):
        self.added.append((ip, mac, name, kwargs))

    def del_host(self, mac):
        if _StubOmapi.raise_on_delete is not None:
            raise _StubOmapi.raise_on_delete
        self.deleted.append(mac)

    def close(self):
        self.closed = True


@pytest.fixture
def omapi(monkeypatch):
    """A fake `pypureomapi`, whatever is installed; returns the module."""
    module = types.ModuleType("pypureomapi")

    class OmapiError(Exception):
        pass

    class OmapiErrorNotFound(OmapiError):
        pass

    module.Omapi = _StubOmapi
    module.OmapiError = OmapiError
    module.OmapiErrorNotFound = OmapiErrorNotFound
    monkeypatch.setitem(sys.modules, "pypureomapi", module)
    monkeypatch.setattr(_StubOmapi, "instances", [])
    monkeypatch.setattr(_StubOmapi, "raise_on_delete", None)
    return module


def test_connect_picks_the_dhcpd_backend():
    server = dhcpctl.connect("dhcpd://10.0.0.1/")
    assert isinstance(server, DHCPDBackend)
    assert (server.hostname, server.port) == ("10.0.0.1", 7911)


def test_add_sends_one_host_with_rendered_statements(omapi, reservation):
    server = dhcpctl.connect("dhcpd://10.0.0.1:7911/?domain-name=example.com")
    server.add(
        reservation(
            server,
            {"boot-file-name": "pxelinux.0", "next-server": "10.0.0.2"},
            defaults={"router": "10.0.0.1"},
        )
    )

    connection = _StubOmapi.instances[-1]
    assert connection.closed
    assert connection.args[:2] == ("10.0.0.1", 7911)
    ip, mac, name, kwargs = connection.added[0]
    assert (ip, mac, name) == ("10.0.0.10", "aa:bb:cc:dd:ee:ff", "web01")
    statements = kwargs["statements"]
    assert 'filename "pxelinux.0";' in statements
    assert "next-server 10.0.0.2;" in statements
    assert 'option domain-name "example.com";' in statements
    assert "option routers 10.0.0.1;" in statements  # dhcpd's plural spelling


def test_a_host_with_no_options_sends_no_statements(omapi, reservation):
    server = dhcpctl.connect("dhcpd://10.0.0.1/")
    server.add(reservation())
    assert _StubOmapi.instances[-1].added[0][3]["statements"] is None


def test_remove_deletes_by_mac_and_tolerates_a_missing_host(omapi, reservation):
    server = dhcpctl.connect("dhcpd://10.0.0.1/")
    server.remove(reservation())
    assert _StubOmapi.instances[-1].deleted == ["aa:bb:cc:dd:ee:ff"]

    _StubOmapi.raise_on_delete = omapi.OmapiErrorNotFound()
    server.remove(reservation())  # must not raise
    assert _StubOmapi.instances[-1].closed


def test_another_omapi_error_propagates(omapi, reservation):
    server = dhcpctl.connect("dhcpd://10.0.0.1/")
    _StubOmapi.raise_on_delete = omapi.OmapiError("server said no")
    with pytest.raises(omapi.OmapiError):
        server.remove(reservation())
    # Closed even so.
    assert _StubOmapi.instances[-1].closed


@pytest.mark.parametrize(
    "hostile",
    [
        'x"; option domain-name-servers 6.6.6.6; #',
        'x\\; filename "evil"',
        'plain " quote',
    ],
)
def test_a_hostile_text_value_cannot_end_its_statement(hostile):
    statements = render_statements(DHCPOptions({"domain-name": hostile}))
    # Exactly one statement: one unescaped `;` at the very end.
    body = statements.rstrip(";")
    assert ";" not in _outside_quotes(body), statements
    assert statements.startswith('option domain-name "')
    assert statements.endswith('";')


def _outside_quotes(text: str) -> str:
    """The parts of `text` that are not inside a quoted, escaped string."""
    out, inside, escaped = [], False, False
    for ch in text:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            inside = not inside
            continue
        if not inside:
            out.append(ch)
    return "".join(out)


def test_a_newline_in_a_value_is_refused():
    with pytest.raises(dhcpctl.ConfigError, match="newline"):
        render_statements(DHCPOptions({"domain-name": "one\ntwo"}))


def test_a_non_address_where_an_address_belongs_is_refused():
    with pytest.raises(dhcpctl.ConfigError, match="address or number"):
        render_statements(DHCPOptions({"router": "not-an-address"}))


def test_a_list_of_addresses_is_comma_separated():
    statements = render_statements(
        DHCPOptions({"domain-name-servers": ["10.0.0.53", "10.0.0.54"]})
    )
    assert statements == "option domain-name-servers 10.0.0.53, 10.0.0.54;"


def test_raw_lines_are_appended_verbatim():
    statements = render_statements(
        DHCPOptions({"router": "10.0.0.1"}), ['ddns-hostname "web01";']
    )
    assert statements.endswith('ddns-hostname "web01";')


def test_a_numeric_option_becomes_a_dhcp_option_code():
    assert "option dhcp-option-252" in render_statements(
        DHCPOptions({"option-252": "10.0.0.2"})
    )
    assert "option dhcp-option-252" in render_statements(
        DHCPOptions({"252": "10.0.0.2"})
    )


def test_a_keyname_without_a_secret_is_reported(omapi):
    server = dhcpctl.connect("dhcpd://10.0.0.1:7911/?keyname=omapi_key")
    with pytest.raises(dhcpctl.ConfigError, match="omapi_key secret"):
        server.omapi()


def test_the_key_comes_from_the_secret(omapi):
    server = dhcpctl.connect(
        "dhcpd://10.0.0.1:7911/?keyname=omapi_key",
        secrets={"omapi_key": "c2VjcmV0"},
    )
    connection = server.omapi()
    assert connection.args == ("10.0.0.1", 7911, b"omapi_key", b"c2VjcmV0")
    assert connection.kwargs == {"timeout": 30}


def test_a_keyfile_outranks_the_secret(omapi, tmp_path):
    keyfile = tmp_path / "omapi.key"
    keyfile.write_text("ZmlsZQ==\n", encoding="utf-8")
    server = dhcpctl.connect(
        f"dhcpd://10.0.0.1/?keyname=k&keyfile={keyfile.as_posix()}",
        secrets={"omapi_key": "c2VjcmV0"},
    )
    assert server.omapi().args[2:] == (b"k", b"ZmlsZQ==")


def test_no_keyname_connects_unauthenticated(omapi):
    connection = dhcpctl.connect("dhcpd://10.0.0.1/").omapi()
    assert connection.args[2:] == (None, None)


def test_without_pypureomapi_the_extra_is_named(monkeypatch):
    server = dhcpctl.connect("dhcpd://10.0.0.1/")
    monkeypatch.setitem(sys.modules, "pypureomapi", None)
    with pytest.raises(dhcpctl.BackendUnavailableError, match=r"dhcpctl\[dhcpd\]"):
        server.omapi()


@pytest.mark.parametrize("mac", [None, "00:00:00:00:00:00"])
def test_a_client_without_a_mac_is_named(omapi, reservation, mac):
    server = dhcpctl.connect("dhcpd://10.0.0.1/")
    with pytest.raises(dhcpctl.MissingMACError, match="nomac"):
        server.add(reservation(name="nomac", mac=mac))
    assert _StubOmapi.instances == [], "nothing is sent for a client it cannot name"


def test_the_recipe_header_names_the_owner(reservation, ipxe):
    server = dhcpctl.connect("dhcpd://10.0.0.1/", owner="netboot")
    assert server.condition_recipe(reservation(), ipxe).startswith("# netboot:")


# -- extras ----------------------------------------------------------------

#: What dhcpd is told, in its own language, to chainload iPXE.
IPXE_DHCPD = (
    'if exists user-class and option user-class = "iPXE" '
    '{ filename "boot.ipxe"; } else { filename "undionly.kpxe"; }'
)


def test_dhcpd_emits_the_conditional_in_its_statements(omapi, reservation):
    server = dhcpctl.connect("dhcpd://dhcp01/?raw.dhcpd=" + IPXE_DHCPD)
    server.add(reservation(server, {"boot-file-name": "undionly.kpxe"}))
    statements = _StubOmapi.instances[-1].added[0][3]["statements"]
    # The modelled option is still there, and the escape hatch follows it, so a
    # conditional written last is what wins in dhcpd.
    assert 'filename "undionly.kpxe";' in statements
    assert statements.index("undionly.kpxe") < statements.index("user-class")
    assert IPXE_DHCPD in statements


def test_dhcpd_keep_uses_the_remove_phase_extras(omapi, reservation):
    server = dhcpctl.connect("dhcpd://dhcp01/?raw.dhcpd=a;&raw.dhcpd.remove=b;")
    r = reservation(server, completion={"keep": True})
    server.add(r)
    server.complete(r)
    added, kept = (c.added[0][3]["statements"] for c in _StubOmapi.instances)
    assert added == "a;"
    assert kept == "b;"
