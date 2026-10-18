"""Secrets: the caller's, else the URI's user and password.

Whatever the source, a password never appears in `str`, `repr` or a message.
"""

import sys
import types

import pytest

import dhcpctl


class _Recorder(dhcpctl.DHCPServer):
    SETTINGS = frozenset({"region"})


@pytest.fixture
def recorder():
    dhcpctl.register_backend("rec", _Recorder)
    return lambda uri, **kw: dhcpctl.connect(uri, **kw)


def test_the_uri_supplies_user_and_password(recorder):
    server = recorder("rec://admin:s3cret@host/")
    assert server.secret("user") == "admin"
    assert server.secret("password") == "s3cret"


def test_the_caller_overrides_the_uri(recorder):
    server = recorder(
        "rec://admin:s3cret@host/", secrets={"user": "other", "password": "vault"}
    )
    assert server.secret("user") == "other"
    assert server.secret("password") == "vault"


def test_a_caller_none_keeps_the_uris_and_empty_is_empty(recorder):
    server = recorder(
        "rec://admin:s3cret@host/", secrets={"user": None, "password": ""}
    )
    assert server.secret("user") == "admin"
    assert server.secret("password") == ""


def test_the_caller_fills_in_what_the_uri_lacks(recorder):
    asked = []

    def source(key):
        asked.append(key)
        return {"password": "vault"}.get(key)

    server = recorder("rec://admin@host/", secrets=source)
    assert asked == [], "nothing is asked for at construction"
    assert server.secret("user") == "admin"
    assert server.secret("password") == "vault"
    assert asked == ["user", "password"]


def test_a_percent_encoded_password_is_decoded(recorder):
    server = recorder("rec://admin:p%40ss%3Aword@host/")
    assert server.secret("password") == "p@ss:word"


@pytest.mark.parametrize(
    "uri, shown",
    [
        (
            "rec://admin:s3cret@host:99/?region=eu",
            "rec://admin:***@host:99/?region=eu",
        ),
        ("rec://admin@host/", "rec://admin@host/"),
        ("rec://host/", "rec://host/"),
        ("rec://:s3cret@host/", "rec://:***@host/"),
    ],
)
def test_the_password_is_redacted_wherever_the_server_is_shown(recorder, uri, shown):
    server = recorder(uri)
    assert server.uri == uri, "the URI itself is kept as given"
    assert str(server) == shown == server.redacted_uri
    assert "s3cret" not in repr(server)


def test_a_refusal_message_does_not_carry_the_password(recorder, reservation):
    server = recorder("rec://admin:s3cret@host/")
    condition = dhcpctl.parse_conditions(
        {"ipxe": {"match": {"user-class": "iPXE"}, "options": {"router": "1.1.1.1"}}}
    )["ipxe"]
    with pytest.raises(dhcpctl.ConditionUnsupportedError) as excinfo:
        server.ensure_condition(reservation(), condition)
    assert "s3cret" not in str(excinfo.value)
    assert "admin:***@host" in str(excinfo.value)


def test_kea_takes_its_account_from_the_caller_too():
    server = dhcpctl.connect(
        "kea://kea.example/", secrets={"user": "svc", "password": "vault"}
    )
    assert server.auth == ("svc", "vault")


@pytest.fixture
def winrm(monkeypatch):
    module = types.ModuleType("winrm")
    module.sessions = []

    class Session:
        def __init__(self, endpoint, auth=None, transport=None):
            self.auth = auth
            module.sessions.append(self)

        def run_ps(self, script):
            return types.SimpleNamespace(
                status_code=0, std_out=b'{"ok": true}', std_err=b""
            )

    module.Session = Session
    monkeypatch.setitem(sys.modules, "winrm", module)
    return module


def test_windhcp_takes_the_winrm_password_from_the_uri(winrm, reservation):
    server = dhcpctl.connect("windhcp://admin:s3cret@dhcp01/?transport=winrm")
    server.remove(reservation())
    assert winrm.sessions[0].auth == ("admin", "s3cret")
    assert "s3cret" not in repr(server)


def test_a_callers_winrm_password_overrides_the_uris(winrm, reservation):
    server = dhcpctl.connect(
        "windhcp://admin:s3cret@dhcp01/?transport=winrm",
        secrets={"password": "vault"},
    )
    server.remove(reservation())
    assert winrm.sessions[0].auth == ("admin", "vault")


@pytest.fixture
def omapi(monkeypatch):
    module = types.ModuleType("pypureomapi")

    class Omapi:
        def __init__(self, *args, **kwargs):
            self.args = args

    module.Omapi = Omapi
    monkeypatch.setitem(sys.modules, "pypureomapi", module)
    return module


def test_dhcpd_takes_key_name_and_key_from_the_uri(omapi):
    server = dhcpctl.connect("dhcpd://omapi_key:c2VjcmV0@10.0.0.1/")
    assert server.keyname == "omapi_key"
    assert server.omapi().args[2:] == (b"omapi_key", b"c2VjcmV0")
    assert "c2VjcmV0" not in repr(server)


def test_dhcpd_keyname_setting_and_keyfile_outrank_the_uri(omapi, tmp_path):
    keyfile = tmp_path / "omapi.key"
    keyfile.write_text("ZmlsZQ==\n", encoding="utf-8")
    server = dhcpctl.connect(
        f"dhcpd://user:c2VjcmV0@10.0.0.1/?keyname=k&keyfile={keyfile.as_posix()}"
    )
    assert server.omapi().args[2:] == (b"k", b"ZmlsZQ==")


def test_dhcpd_with_only_a_uri_key_name_reports_the_missing_key(omapi):
    server = dhcpctl.connect("dhcpd://omapi_key@10.0.0.1/")
    with pytest.raises(dhcpctl.ConfigError, match="password in the URI"):
        server.omapi()
