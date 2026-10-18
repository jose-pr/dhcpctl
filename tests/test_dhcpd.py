"""The ISC dhcpd backend, against a stub OMAPI module.

`statements` is a fragment of dhcpd's config language, so most of these tests
are about values that must not be able to end a statement and start another.
"""

import sys
import types

import pytest

import dhcpctl
from dhcpctl import PYDHCP_CODES
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

    def create_host(self, ip, mac, name, statements="", group=None):
        self.added.append(
            (ip, mac, name, {"statements": statements or None, "group": group})
        )

    def group_exists(self, name):
        return False

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
    # The stub stands in for the whole connection, the backend's own calls too.
    monkeypatch.setattr(
        "dhcpctl.backends._dhcpd._connection_class", lambda pypureomapi: _StubOmapi
    )
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
    server = dhcpctl.connect("dhcpd://10.0.0.1:7911/")
    server.add(
        reservation(
            server,
            {"filename": "pxelinux.0"},
            defaults={"router": "10.0.0.1", "domain-name": "example.com"},
            next_server="10.0.0.2",
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
    # next-server is a statement of its own, after the options.
    assert statements.endswith("next-server 10.0.0.2;")


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
    statements = render_statements(PYDHCP_CODES.lease({"domain-name": hostile}))
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
        render_statements(PYDHCP_CODES.lease({"domain-name": "one\ntwo"}))


def test_a_non_address_where_an_address_belongs_is_refused():
    # The option's codec refuses it before dhcpd's renderer sees it.
    with pytest.raises(dhcpctl.ConfigError, match=r"option 3 \(ROUTER\) cannot hold"):
        render_statements(PYDHCP_CODES.lease({"router": "not-an-address"}))


def test_an_opaque_option_is_written_as_colon_separated_octets():
    assert render_statements(PYDHCP_CODES.lease({"option-224": b"\x01\x02"})) == (
        "option unknown-224 01:02;"
    )


def test_a_boolean_option_is_written_as_dhcpd_reads_it():
    # dhcpd has no name here for it, so it gets the octets.
    assert render_statements(PYDHCP_CODES.lease({"ip-forwarding": True})) == (
        "option unknown-19 01;"
    )


def test_a_list_of_addresses_is_comma_separated():
    statements = render_statements(
        PYDHCP_CODES.lease({"dns": ["10.0.0.53", "10.0.0.54"]})
    )
    assert statements == "option domain-name-servers 10.0.0.53, 10.0.0.54;"


def test_extras_are_appended_verbatim():
    statements = render_statements(
        PYDHCP_CODES.lease({"router": "10.0.0.1"}), ['ddns-hostname "web01";']
    )
    assert statements.endswith('ddns-hostname "web01";')


def test_an_option_dhcpd_has_no_name_for_is_unknown_n():
    # dhcpd(8) parses `unknown-<n>`; `dhcp-option-<n>` is a syntax error.
    assert render_statements(PYDHCP_CODES.lease({"option-252": "10.0.0.2"})) == (
        'option unknown-252 "10.0.0.2";'
    )
    assert render_statements(PYDHCP_CODES.lease({224: b"\x01"})) == (
        "option unknown-224 01;"
    )


def test_header_fields_are_statements_after_the_options_before_the_raw_lines():
    lease = PYDHCP_CODES.lease(
        {"router": "10.0.0.1", "next-server": "10.0.0.2", "file": "a", "sname": "t"}
    )
    statements = render_statements(lease, ["x;"])
    assert statements == (
        'option routers 10.0.0.1; filename "a"; server-name "t"; '
        "next-server 10.0.0.2; x;"
    )
    assert render_statements(PYDHCP_CODES.lease({"next-server": "10.0.0.2"})) == (
        "next-server 10.0.0.2;"
    )
    router = PYDHCP_CODES.lease({"router": "10.0.0.1"})
    assert "next-server" not in render_statements(router)
    assert "filename" not in render_statements(router)


def test_option_67_is_an_option_not_the_filename_statement():
    statements = render_statements(PYDHCP_CODES.lease({"bootfile-name": "a"}))
    assert statements == 'option bootfile-name "a";'


def test_a_reservation_next_server_alone_is_sent(omapi, reservation):
    server = dhcpctl.connect("dhcpd://10.0.0.1/")
    server.add(reservation(next_server="10.0.0.2"))
    assert _StubOmapi.instances[-1].added[0][3]["statements"] == (
        "next-server 10.0.0.2;"
    )


def test_a_host_without_an_address_is_refused_before_omapi(omapi, reservation):
    # OMAPI packs the host's address; there is no fixed host without one.
    server = dhcpctl.connect("dhcpd://10.0.0.1/")
    with pytest.raises(dhcpctl.ConfigError, match="no ip address"):
        server.add(reservation(ip=None))
    assert _StubOmapi.instances == [] or not _StubOmapi.instances[-1].added


def test_an_unspecified_next_server_is_never_written(omapi, reservation):
    server = dhcpctl.connect("dhcpd://10.0.0.1/")
    server.add(reservation(next_server=None))
    _, _, _, kwargs = _StubOmapi.instances[-1].added[0]
    assert "next-server" not in (kwargs["statements"] or "")


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
    server = dhcpctl.connect("dhcpd://dhcp01/")
    server.add(
        reservation(server, {"filename": "undionly.kpxe"}, extras={"add": [IPXE_DHCPD]})
    )
    statements = _StubOmapi.instances[-1].added[0][3]["statements"]
    # The modelled option is still there, and the extras follow it, so a
    # conditional written last is what wins in dhcpd.
    assert 'filename "undionly.kpxe";' in statements
    assert statements.index("undionly.kpxe") < statements.index("user-class")
    assert IPXE_DHCPD in statements


def test_dhcpd_keep_uses_the_remove_phase_extras(omapi, reservation):
    server = dhcpctl.connect("dhcpd://dhcp01/")
    r = reservation(
        server, completion={"keep": True}, extras={"add": ["a;"], "remove": ["b;"]}
    )
    server.add(r)
    server.complete(r)
    added, kept = (c.added[0][3]["statements"] for c in _StubOmapi.instances)
    assert added == "a;"
    assert kept == "b;"


def test_a_text_option_pydhcp_knows_is_quoted():
    # root-path is a String codec, so dhcpd gets a string literal.
    assert render_statements(PYDHCP_CODES.lease({"root-path": "/srv/nfs root"})) == (
        'option unknown-17 "/srv/nfs root";'
    )
