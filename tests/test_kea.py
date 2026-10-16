"""The Kea backend, against a stub control agent.

No test reaches a Kea: `requests.post` is replaced by a recorder that answers
with the shapes Kea really returns (`result` 0/1/2/3).
"""

import sys

import pytest
import requests

import dhcpctl
from dhcpctl.backends import KeaBackend


class _Response:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeRequests:
    """Stands in for `requests.post`, one queued reply per command."""

    def __init__(self, replies):
        self.replies = dict(replies)
        self.posted = []

    def post(self, url, json=None, auth=None, timeout=None):
        self.posted.append((url, json, auth))
        command = json["command"]
        reply = self.replies.get(command, {"result": 0, "text": "ok"})
        if isinstance(reply, Exception):
            raise reply
        return _Response([reply] if isinstance(reply, dict) else reply)

    def commands(self):
        return [payload["command"] for _, payload, _ in self.posted]


@pytest.fixture
def kea_server(monkeypatch):
    def build(uri="kea://10.0.0.1:8000/", replies=None, **kwargs):
        server = dhcpctl.connect(uri, **kwargs)
        fake = _FakeRequests(replies or {})
        monkeypatch.setattr(requests, "post", fake.post)
        return server, fake

    return build


@pytest.fixture
def lan(reservation):
    """`web01` in subnet 44, declared on its scope."""

    def build(*args, **kwargs):
        kwargs.setdefault("subnet_id", 44)
        return reservation(*args, **kwargs)

    return build


def test_connect_picks_the_kea_backend_for_both_schemes():
    assert isinstance(dhcpctl.connect("kea://h/"), KeaBackend)
    assert isinstance(dhcpctl.connect("keas://h/"), KeaBackend)


def test_add_posts_one_reservation_with_fields_and_options(kea_server, lan):
    server, fake = kea_server("kea://10.0.0.1:8000/?domain-name-servers=10.0.0.53")
    server.add(lan(server, {"boot-file-name": "pxelinux.0", "next-server": "10.0.0.2"}))

    assert len(fake.posted) == 1
    url, payload, _ = fake.posted[0]
    assert url == "http://10.0.0.1:8000/"
    assert payload["command"] == "reservation-add"
    assert payload["service"] == ["dhcp4"]
    reservation = payload["arguments"]["reservation"]
    assert reservation["subnet-id"] == 44
    assert reservation["hw-address"] == "aa:bb:cc:dd:ee:ff"
    assert reservation["ip-address"] == "10.0.0.10"
    # Reservation fields, not option-data entries.
    assert reservation["boot-file-name"] == "pxelinux.0"
    assert reservation["next-server"] == "10.0.0.2"
    assert {"name": "domain-name-servers", "data": "10.0.0.53"} in reservation[
        "option-data"
    ]
    assert not any(
        entry.get("name") in ("boot-file-name", "next-server")
        for entry in reservation["option-data"]
    )
    # No classes asked for, so none named.
    assert "client-classes" not in reservation


def test_the_host_name_option_is_the_hostname_field(kea_server, lan):
    server, fake = kea_server()
    server.add(lan(options={"host-name": "web01.lan"}))
    reservation = fake.posted[0][1]["arguments"]["reservation"]
    assert reservation["hostname"] == "web01.lan"
    assert "option-data" not in reservation


def test_a_multi_valued_option_is_comma_joined(kea_server, lan):
    server, fake = kea_server(
        "kea://10.0.0.1:8000/?domain-name-servers=10.0.0.53&domain-name-servers=10.0.0.54"
    )
    server.add(lan(server))
    reservation = fake.posted[0][1]["arguments"]["reservation"]
    assert reservation["option-data"] == [
        {"name": "domain-name-servers", "data": "10.0.0.53,10.0.0.54"}
    ]


def test_the_service_setting_names_the_daemon(kea_server, lan):
    server, fake = kea_server("kea://10.0.0.1:8000/?service=dhcp6")
    server.add(lan())
    assert fake.posted[0][1]["service"] == ["dhcp6"]


def test_a_numeric_option_uses_its_code(kea_server, lan):
    server, fake = kea_server("kea://10.0.0.1:8000/?option-252=http://proxy/wpad.dat")
    server.add(lan(server))
    reservation = fake.posted[0][1]["arguments"]["reservation"]
    assert {"code": 252, "data": "http://proxy/wpad.dat"} in reservation["option-data"]


def test_remove_sends_reservation_del_and_accepts_not_found(kea_server, lan):
    server, fake = kea_server(
        replies={"reservation-del": {"result": 3, "text": "none"}}
    )
    server.remove(lan())
    payload = fake.posted[0][1]
    assert payload["command"] == "reservation-del"
    assert payload["arguments"] == {
        "subnet-id": 44,
        "identifier-type": "hw-address",
        "identifier": "aa:bb:cc:dd:ee:ff",
    }


def test_a_refused_remove_is_reported(kea_server, lan):
    server, _ = kea_server(replies={"reservation-del": {"result": 1, "text": "boom"}})
    with pytest.raises(dhcpctl.ServerError, match="boom"):
        server.remove(lan())


def test_an_unsupported_result_explains_the_usual_cause(kea_server, lan):
    server, _ = kea_server(
        replies={"reservation-add": {"result": 2, "text": "not supported"}}
    )
    with pytest.raises(dhcpctl.ServerError) as excinfo:
        server.add(lan())
    message = str(excinfo.value)
    assert "not supported" in message
    assert "host_cmds" in message and "read-only" in message


@pytest.mark.parametrize("owner", ["dhcpctl", "netboot"])
def test_an_existing_reservation_is_refused_not_overwritten(kea_server, lan, owner):
    server, _ = kea_server(
        replies={
            "reservation-add": {"result": 1, "text": "database exists error"},
        },
        owner=owner,
    )
    with pytest.raises(
        dhcpctl.ReservationExistsError, match=f"{owner} does not overwrite"
    ):
        server.add(lan())


def test_another_result_1_is_a_plain_server_error(kea_server, lan):
    server, _ = kea_server(
        replies={"reservation-add": {"result": 1, "text": "bad address"}}
    )
    with pytest.raises(dhcpctl.ServerError) as excinfo:
        server.add(lan())
    assert not isinstance(excinfo.value, dhcpctl.ReservationExistsError)


def test_the_subnet_id_is_discovered_from_the_scope_network(kea_server, reservation):
    server, fake = kea_server(
        replies={
            "config-get": {
                "result": 0,
                "arguments": {
                    "Dhcp4": {
                        "subnet4": [
                            {"id": 7, "subnet": "192.168.0.0/24"},
                            {"id": 8, "subnet": "10.0.0.0/24"},
                        ]
                    }
                },
            }
        }
    )
    server.add(reservation())  # no subnet_id
    assert fake.commands() == ["config-get", "reservation-add"]
    assert fake.posted[1][1]["arguments"]["reservation"]["subnet-id"] == 8

    # Resolved once per scope, then cached.
    server.add(reservation())
    assert fake.commands().count("config-get") == 1


def test_an_unmatched_scope_refuses_rather_than_guessing(kea_server, reservation):
    server, _ = kea_server(
        replies={
            "config-get": {"result": 0, "arguments": {"Dhcp4": {"subnet4": []}}},
        }
    )
    with pytest.raises(dhcpctl.ConfigError, match="subnet_id"):
        server.add(reservation())


def test_a_scope_without_a_network_or_id_refuses_without_asking(
    kea_server, reservation
):
    server, fake = kea_server()
    with pytest.raises(dhcpctl.ConfigError, match="subnet_id"):
        server.add(reservation(network=None))
    assert fake.posted == []


@pytest.mark.parametrize("mac", [None, "00:00:00:00:00:00"])
def test_a_client_without_a_mac_is_named(kea_server, lan, mac):
    server, fake = kea_server()
    with pytest.raises(dhcpctl.MissingMACError, match="nomac"):
        server.add(lan(name="nomac", mac=mac))
    with pytest.raises(dhcpctl.MissingMACError, match="nomac"):
        server.remove(lan(name="nomac", mac=mac))
    assert fake.posted == []


def test_https_and_auth_come_from_the_uri():
    server = dhcpctl.connect("keas://admin:secret@kea.example:8443/")
    assert server.endpoint == "https://kea.example:8443/"
    assert server.auth == ("admin", "secret")


def test_the_password_secret_fills_in_for_one_the_uri_lacks(kea_server, lan):
    server, fake = kea_server(
        "kea://admin@kea.example/", secrets={"password": "from-vault"}
    )
    assert server.endpoint == "http://kea.example:8000/"
    server.add(lan())
    assert fake.posted[0][2] == ("admin", "from-vault")


def test_no_user_means_no_auth():
    assert dhcpctl.connect("kea://kea.example/").auth is None


def test_a_transport_failure_is_a_server_error(kea_server, lan):
    server, _ = kea_server(
        replies={"reservation-add": requests.ConnectionError("refused")}
    )
    with pytest.raises(dhcpctl.ServerError, match="refused"):
        server.add(lan())


def test_an_empty_reply_is_a_server_error(kea_server, lan):
    server, _ = kea_server(replies={"reservation-add": []})
    with pytest.raises(dhcpctl.ServerError, match="no response object"):
        server.add(lan())


def test_without_requests_the_extra_is_named(monkeypatch):
    server = dhcpctl.connect("kea://10.0.0.1:8000/")
    monkeypatch.setitem(sys.modules, "requests", None)
    with pytest.raises(dhcpctl.BackendUnavailableError, match=r"dhcpctl\[kea\]"):
        server.command("config-get")


# -- extras ----------------------------------------------------------------


def test_raw_entries_are_merged_as_option_data(kea_server, lan):
    server, fake = kea_server()
    # A Kea fragment is an `option-data` entry, passed through untouched.
    server.add(lan(extras={"add": [{"code": 250, "data": "x"}]}))
    reservation = fake.posted[0][1]["arguments"]["reservation"]
    assert {"code": 250, "data": "x"} in reservation["option-data"]


def test_kea_appends_the_uri_extra_option_data(kea_server, lan):
    server, fake = kea_server("kea://ctrl01/?raw.kea=" + "not-a-real-option")
    server.add(lan(server))
    reservation = fake.posted[0][1]["arguments"]["reservation"]
    assert "not-a-real-option" in reservation["option-data"]
