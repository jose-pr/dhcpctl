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
    server, fake = kea_server()
    server.add(
        lan(
            server,
            {"boot-file-name": "pxelinux.0"},
            defaults={"domain-name-servers": "10.0.0.53"},
            next_server="10.0.0.2",
        )
    )

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
    assert {"code": 6, "data": "10.0.0.53"} in reservation["option-data"]
    assert not any(
        entry.get("code") in (66, 67) for entry in reservation["option-data"]
    )
    # No classes asked for, so none named.
    assert "client-classes" not in reservation


def test_a_reservation_without_next_server_has_no_such_field(kea_server, lan):
    server, fake = kea_server()
    server.add(lan(server, {"boot-file-name": "pxelinux.0"}))
    reservation = fake.posted[0][1]["arguments"]["reservation"]
    assert "next-server" not in reservation
    assert "option-data" not in reservation


def test_next_server_alone_is_a_reservation_field(kea_server, lan):
    server, fake = kea_server()
    server.add(lan(next_server="10.0.0.2"))
    reservation = fake.posted[0][1]["arguments"]["reservation"]
    assert reservation["next-server"] == "10.0.0.2"
    assert "option-data" not in reservation


@pytest.mark.parametrize("unset", [None, "0.0.0.0"])
def test_an_unspecified_address_is_no_field(kea_server, lan, unset):
    server, fake = kea_server()
    server.add(lan(ip=unset, next_server=unset))
    reservation = fake.posted[0][1]["arguments"]["reservation"]
    assert "ip-address" not in reservation
    assert "next-server" not in reservation
    assert reservation["hw-address"] == "aa:bb:cc:dd:ee:ff"


def test_the_host_name_option_is_the_hostname_field(kea_server, lan):
    server, fake = kea_server()
    server.add(lan(server, {"host-name": "web01.lan"}))
    reservation = fake.posted[0][1]["arguments"]["reservation"]
    assert reservation["hostname"] == "web01.lan"
    assert "option-data" not in reservation


def test_a_multi_valued_option_is_comma_joined(kea_server, lan):
    server, fake = kea_server()
    server.add(lan(server, {"domain-name-servers": ["10.0.0.53", "10.0.0.54"]}))
    reservation = fake.posted[0][1]["arguments"]["reservation"]
    assert reservation["option-data"] == [{"code": 6, "data": "10.0.0.53,10.0.0.54"}]


def test_the_service_setting_names_the_daemon(kea_server, lan):
    server, fake = kea_server("kea://10.0.0.1:8000/?service=dhcp4")
    server.add(lan())
    assert fake.posted[0][1]["service"] == ["dhcp4"]


@pytest.mark.parametrize("service", ["dhcp6", "d2"])
def test_a_service_other_than_dhcp4_is_refused(service):
    with pytest.raises(dhcpctl.ConfigError, match="dhcp4 only"):
        dhcpctl.connect(f"kea://k/?service={service}")


def test_keep_falls_back_to_delete_and_add_without_reservation_update(kea_server, lan):
    server, fake = kea_server(
        "kea://k/", {"reservation-update": {"result": 2, "text": "unsupported"}}
    )
    server.keep(lan(completion={"keep": True}))
    assert fake.commands() == [
        "reservation-update",
        "reservation-del",
        "reservation-add",
    ]


@pytest.mark.parametrize("failing", ["reservation-update", "reservation-add"])
def test_every_step_of_a_rewrite_is_checked(kea_server, lan, failing):
    replies = {failing: {"result": 1, "text": "duplicate entry"}}
    if failing == "reservation-add":
        replies["reservation-update"] = {"result": 2, "text": "unsupported"}
    server, _ = kea_server("kea://k/", replies)
    with pytest.raises(dhcpctl.ServerError, match="duplicate entry"):
        server.keep(lan(completion={"keep": True}))


def test_detaching_a_class_rewrites_the_reservation_and_checks_it(kea_server, lan):
    server, fake = kea_server(
        "kea://k/", {"reservation-update": {"result": 1, "text": "no such host"}}
    )
    condition = dhcpctl.parse_conditions(
        {"ipxe": {"match": {"user-class": "iPXE"}, "options": {"file": "b"}}}, "t"
    )["ipxe"]
    with pytest.raises(dhcpctl.ServerError, match="no such host"):
        server.remove_condition_member(lan(), condition)


def test_keep_writes_the_remove_phase_extras(kea_server, lan):
    server, fake = kea_server("kea://k/")
    server.keep(
        lan(
            completion={"keep": True},
            extras={
                "add": [{"code": 250, "data": "a"}],
                "remove": [{"code": 251, "data": "r"}],
            },
        )
    )
    entry = fake.posted[0][1]["arguments"]["reservation"]
    codes = [item["code"] for item in entry.get("option-data", [])]
    assert 251 in codes and 250 not in codes


def test_a_subnet_inside_a_shared_network_is_found(kea_server, reservation):
    config = {
        "result": 0,
        "arguments": {
            "Dhcp4": {
                "subnet4": [{"id": 1, "subnet": "192.168.0.0/24"}],
                "shared-networks": [
                    {"name": "lab", "subnet4": [{"id": 7, "subnet": "10.0.0.0/24"}]}
                ],
            }
        },
    }
    server, fake = kea_server("kea://k/", {"config-get": config})
    server.add(reservation(server))
    assert fake.posted[-1][1]["arguments"]["reservation"]["subnet-id"] == 7


def test_a_numeric_option_uses_its_code(kea_server, lan):
    server, fake = kea_server()
    server.add(lan(server, {"option-252": "http://proxy/wpad.dat"}))
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


def test_extra_entries_are_merged_as_option_data(kea_server, lan):
    server, fake = kea_server()
    # A Kea fragment is an `option-data` entry, passed through untouched.
    server.add(lan(extras={"add": [{"code": 250, "data": "x"}]}))
    reservation = fake.posted[0][1]["arguments"]["reservation"]
    assert {"code": 250, "data": "x"} in reservation["option-data"]


def test_kea_appends_an_extra_it_does_not_check(kea_server, lan):
    server, fake = kea_server("kea://ctrl01/")
    server.add(lan(server, extras={"add": ["not-a-real-option"]}))
    reservation = fake.posted[0][1]["arguments"]["reservation"]
    assert "not-a-real-option" in reservation["option-data"]
