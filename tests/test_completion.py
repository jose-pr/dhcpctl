"""Completion: what a finished client's entry becomes.

The failure this prevents: a machine that still receives `boot-file-name` after
its install finishes boots the installer again. Removing the reservation stops
that and throws away the fixed address; keeping it without boot options, or with
a `sanboot` script, stops it and does not.
"""

import pytest

import dhcpctl
from dhcpctl import BOOT_OPTIONS, Completion, DHCPOptions, parse_completion

SANBOOT = {"keep": True, "options": {"boot-file-name": "sanboot.ipxe"}}

#: What an installing client is served: its scope's options plus the boot ones.
INSTALLING = {
    "router": "10.0.0.1",
    "subnet-mask": "255.255.255.0",
    "broadcast-address": "10.0.0.255",
    "boot-file-name": "undionly.kpxe",
    "tftp-server-name": "10.0.0.2",
}


@pytest.fixture
def installing(reservation):
    def build(completion=None, **kwargs):
        kwargs.setdefault("options", INSTALLING)
        kwargs.setdefault("subnet_id", 1)
        return reservation(completion=completion, **kwargs)

    return build


# -- the model --------------------------------------------------------------


def test_removing_the_entry_is_the_default():
    completion = Completion()
    assert completion.keep is False
    assert not completion
    assert completion.options == {}


def test_nothing_declared_parses_to_none():
    assert parse_completion(None, "debian") is None


def test_keep_without_options_drops_only_the_boot_options():
    completion = parse_completion({"keep": True}, "debian")
    assert completion
    kept = completion.apply_to(DHCPOptions(INSTALLING))
    assert not any(name in kept for name in BOOT_OPTIONS)
    # The options that make a reservation worth keeping are still there.
    assert kept["router"] == "10.0.0.1" and "subnet-mask" in kept


def test_keep_with_options_replaces_rather_than_merges():
    completion = parse_completion(SANBOOT, "debian")
    kept = completion.apply_to(DHCPOptions(INSTALLING))
    assert kept["boot-file-name"] == "sanboot.ipxe"
    # A merge would have left the installer's tftp server in place.
    assert "tftp-server-name" not in kept


def test_apply_to_keeps_raw_and_leaves_its_input_alone():
    options = DHCPOptions(INSTALLING, raw={"dnsmasq": ["x"]})
    kept = Completion(keep=True).apply_to(options)
    assert kept.raw_for("dnsmasq") == ["x"]
    assert options["boot-file-name"] == "undionly.kpxe"


@pytest.mark.parametrize(
    "declared, message",
    [
        ("remove", "must be a mapping"),
        ({"keep": "yes"}, "must be true or false"),
        ({"keep": True, "zzz": 1}, "unknown key"),
        ({"keep": True, "options": ["boot-file-name"]}, "must be a mapping"),
        ({"keep": True, "options": {"nonsense": "x"}}, "unknown dhcp option"),
        ({"options": {"boot-file-name": "x"}}, "nowhere to go"),
    ],
)
def test_a_malformed_completion_names_the_mistake(declared, message):
    with pytest.raises(dhcpctl.ConfigError, match=message) as excinfo:
        parse_completion(declared, "debian")
    assert "'debian'" in str(excinfo.value)


# -- windhcp ---------------------------------------------------------------


def _sent(uri, reservation):
    server = dhcpctl.connect(uri)
    sent = []
    server.run = lambda payload, body: sent.append((payload, body))
    server.complete(reservation)
    return sent


def test_windhcp_default_completion_removes_the_reservation(installing):
    sent = _sent("windhcp://dhcp01/", installing())
    assert "ClientId" in sent[0][0]
    assert "Remove-DhcpServerv4Reservation" in "\n".join(sent[0][1])


def test_windhcp_keep_sets_the_completion_options_and_removes_the_rest(installing):
    sent = _sent("windhcp://dhcp01/", installing(SANBOOT))
    payload, body = sent[0]
    assert {o["Id"]: o["Value"] for o in payload["Set"]}[67] == ["sanboot.ipxe"]
    assert payload["Remove"] == [66]
    assert "Remove-DhcpServerv4Reservation" not in "\n".join(body)
    # Already-absent is success: completion re-runs.
    assert "-ErrorAction SilentlyContinue" in "\n".join(body)


def test_windhcp_keep_bare_removes_every_boot_option(installing):
    sent = _sent("windhcp://dhcp01/", installing({"keep": True}))
    payload = sent[0][0]
    assert sorted(payload["Remove"]) == [66, 67]
    assert sorted(o["Id"] for o in payload["Set"]) == [1, 3, 28]


# -- dhcpd -----------------------------------------------------------------


class _FakeOmapi:
    def __init__(self, calls):
        self.calls = calls

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.calls.append((name, args, kwargs))

        return record


def _dhcpd_calls(reservation, uri="dhcpd://dhcp01/"):
    server = dhcpctl.connect(uri)
    calls = []
    server.omapi = lambda: _FakeOmapi(calls)
    server.complete(reservation)
    return calls


def test_dhcpd_default_completion_deletes_the_host(installing):
    calls = _dhcpd_calls(installing())
    assert [c[0] for c in calls] == ["del_host", "close"]


def test_dhcpd_keep_supersedes_the_host_in_one_call(installing):
    # One call, so there is no window with the installer's filename still set.
    calls = _dhcpd_calls(installing(SANBOOT))
    assert [c[0] for c in calls] == ["add_host_supersede", "close"]
    statements = calls[0][2]["statements"]
    assert 'filename "sanboot.ipxe";' in statements
    assert "undionly" not in statements


def test_dhcpd_keep_bare_leaves_no_filename(installing):
    calls = _dhcpd_calls(installing({"keep": True}))
    statements = calls[0][2]["statements"] or ""
    assert "filename" not in statements
    assert "option subnet-mask" in statements


# -- kea -------------------------------------------------------------------


def _kea_sent(reservation):
    server = dhcpctl.connect("kea://ctrl01/")
    sent = []

    def command(cmd, arguments=None):
        sent.append((cmd, arguments))
        return {"result": 0}

    server.command = command
    server.complete(reservation)
    return sent


def test_kea_default_completion_deletes_the_reservation(installing):
    assert [cmd for cmd, _ in _kea_sent(installing())] == ["reservation-del"]


def test_kea_keep_upserts_the_reservation_without_boot_fields(installing):
    # reservation-add upserts, so the old reservation survives a failure rather
    # than the client being left with none.
    sent = _kea_sent(installing(SANBOOT))
    assert [cmd for cmd, _ in sent] == ["reservation-add"]
    reservation = dict(sent[0][1])["reservation"]
    assert reservation["boot-file-name"] == "sanboot.ipxe"
    names = [o.get("name") for o in reservation.get("option-data", [])]
    assert "tftp-server-name" not in names


def test_kea_keep_bare_has_no_boot_fields_at_all(installing):
    sent = _kea_sent(installing({"keep": True}))
    reservation = dict(sent[0][1])["reservation"]
    assert "boot-file-name" not in reservation and "next-server" not in reservation


def test_kea_keep_reports_a_refusal(installing):
    server = dhcpctl.connect("kea://ctrl01/")
    server.command = lambda cmd, arguments=None: {"result": 1, "text": "nope"}
    with pytest.raises(dhcpctl.ServerError, match="nope"):
        server.complete(installing({"keep": True}))


# -- dnsmasq ---------------------------------------------------------------


def test_dnsmasq_keep_rewrites_the_region(tmp_path, installing):
    hosts = tmp_path / "h"
    hosts.mkdir()
    opts = tmp_path / "o"
    opts.mkdir()
    uri = f"dnsmasq:///?hostsfile={hosts.as_posix()}&optsfile={opts.as_posix()}"
    server = dhcpctl.connect(uri)
    server.add(installing())
    before = "\n".join(p.read_text() for p in opts.iterdir())
    assert "undionly.kpxe" in before
    server.complete(installing(SANBOOT))
    after = "\n".join(p.read_text() for p in opts.iterdir())
    assert "sanboot.ipxe" in after and "undionly.kpxe" not in after
    # The host line stays, so the address is still reserved.
    assert any(p.read_text().strip() for p in hosts.iterdir())
