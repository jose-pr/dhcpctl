"""Completion: what a finished client's entry becomes.

The failure this prevents: a machine that is still handed a boot file after
its install finishes boots the installer again. Removing the reservation stops
that and throws away the fixed address; keeping it without boot options, or with
a `sanboot` script, stops it and does not.
"""

import pytest

import dhcpctl
import ipaddress

from dhcpctl import (
    BOOT_OPTIONS,
    PYDHCP_CODES,
    UNSPECIFIED,
    Completion,
    parse_completion,
    plain_items,
)

SANBOOT = {"keep": True, "options": {"file": "sanboot.ipxe"}}

#: Keep, with the boot file fetched from another TFTP server than the install's.
SANBOOT_ELSEWHERE = Completion(
    keep=True, lease={"file": "sanboot.ipxe", "next-server": "10.0.0.9"}
)

#: What an installing client is served: its scope's options plus the boot ones.
INSTALLING = {
    "router": "10.0.0.1",
    "subnet-mask": "255.255.255.0",
    "broadcast-address": "10.0.0.255",
    "file": "undionly.kpxe",
    "tftp-server": "10.0.0.2",
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
    assert len(completion.lease.options) == 0
    assert completion.lease.siaddr == UNSPECIFIED and not completion.lease.file


def test_nothing_declared_parses_to_none():
    assert parse_completion(None, "debian") is None


def test_keep_without_options_drops_only_the_boot_options():
    completion = parse_completion({"keep": True}, "debian")
    assert completion
    assert BOOT_OPTIONS == (67, 66)
    kept = completion.apply_to(PYDHCP_CODES.lease(INSTALLING))
    assert not any(int(code) in kept.options for code in BOOT_OPTIONS)
    assert not kept.file
    # The options that make a reservation worth keeping are still there.
    assert dict(plain_items(kept.options)) == {
        3: ["10.0.0.1"],
        1: "255.255.255.0",
        28: "10.0.0.255",
    }


def test_keep_with_options_replaces_rather_than_merges():
    completion = parse_completion(SANBOOT, "debian")
    kept = completion.apply_to(PYDHCP_CODES.lease(INSTALLING))
    assert kept.file == "sanboot.ipxe"
    # A merge would have left the installer's tftp server in place.
    assert 66 not in kept.options


def test_apply_to_leaves_its_input_alone():
    lease = PYDHCP_CODES.lease(INSTALLING)
    Completion(keep=True).apply_to(lease)
    assert lease.file == "undionly.kpxe" and lease.options.get(66) == "10.0.0.2"


def test_header_fields_in_the_options_are_the_completion_lease_fields():
    completion = parse_completion(
        {"keep": True, "options": {"file": "x", "next-server": "10.0.0.9"}},
        "debian",
    )
    assert completion.lease.siaddr == ipaddress.IPv4Address("10.0.0.9")
    assert completion.lease.file == "x"
    assert len(completion.lease.options) == 0


def test_option_67_is_an_option_not_the_file_field():
    completion = parse_completion(
        {"keep": True, "options": {"bootfile-name": "x"}}, "debian"
    )
    assert dict(plain_items(completion.lease.options)) == {67: "x"}
    assert completion.lease.file == ""


@pytest.mark.parametrize(
    "declared, message",
    [
        ("remove", "must be a mapping"),
        ({"keep": "yes"}, "must be true or false"),
        ({"keep": True, "zzz": 1}, "unknown key"),
        ({"keep": True, "options": ["bootfile-name"]}, "must be a mapping"),
        ({"keep": True, "options": {"nonsense": "x"}}, "unknown option"),
        ({"options": {"bootfile-name": "x"}}, "nowhere to go"),
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


def test_dhcpd_keep_deletes_and_creates_the_host(installing):
    # dhcpd refuses to create a host that exists, and OMAPI cannot replace one.
    calls = _dhcpd_calls(installing(SANBOOT))
    assert [c[0] for c in calls] == ["del_host", "create_host", "close"]
    statements = calls[1][2]["statements"]
    assert 'filename "sanboot.ipxe";' in statements
    assert "undionly" not in statements


def test_dhcpd_keep_bare_leaves_no_filename(installing):
    calls = _dhcpd_calls(installing({"keep": True}, next_server="10.0.0.2"))
    statements = calls[1][2]["statements"] or ""
    assert "filename" not in statements and "next-server" not in statements
    assert "option subnet-mask" in statements


def test_dhcpd_keep_writes_the_completion_next_server(installing):
    calls = _dhcpd_calls(installing(SANBOOT_ELSEWHERE, next_server="10.0.0.2"))
    statements = calls[1][2]["statements"]
    assert statements.endswith('filename "sanboot.ipxe"; next-server 10.0.0.9;')
    assert "next-server 10.0.0.2;" not in statements


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


def test_kea_keep_updates_the_reservation_without_boot_fields(installing):
    # reservation-update rewrites it in place: reservation-add refuses one that
    # exists.
    sent = _kea_sent(installing(SANBOOT))
    assert [cmd for cmd, _ in sent] == ["reservation-update"]
    reservation = dict(sent[0][1])["reservation"]
    assert reservation["boot-file-name"] == "sanboot.ipxe"
    codes = [o.get("code") for o in reservation.get("option-data", [])]
    assert 66 not in codes


def test_kea_keep_bare_has_no_boot_fields_at_all(installing):
    sent = _kea_sent(installing({"keep": True}, next_server="10.0.0.2"))
    reservation = dict(sent[0][1])["reservation"]
    assert "boot-file-name" not in reservation and "next-server" not in reservation


def test_kea_keep_sets_the_completion_next_server(installing):
    sent = _kea_sent(installing(SANBOOT_ELSEWHERE, next_server="10.0.0.2"))
    reservation = dict(sent[0][1])["reservation"]
    assert reservation["next-server"] == "10.0.0.9"
    assert reservation["boot-file-name"] == "sanboot.ipxe"


def test_kea_keep_reports_a_refusal(installing):
    server = dhcpctl.connect("kea://ctrl01/")
    server.command = lambda cmd, arguments=None: {"result": 1, "text": "nope"}
    with pytest.raises(dhcpctl.ServerError, match="nope"):
        server.complete(installing({"keep": True}))


# -- dnsmasq ---------------------------------------------------------------


def _dnsmasq(tmp_path):
    hosts = tmp_path / "h"
    hosts.mkdir()
    opts = tmp_path / "o"
    opts.mkdir()
    uri = f"dnsmasq:///?hostsfile={hosts.as_posix()}&optsfile={opts.as_posix()}"
    return dhcpctl.connect(uri), hosts, opts


@pytest.fixture(autouse=True)
def hups(monkeypatch):
    """Completion takes entries away, so a directory-mode dnsmasq is SIGHUPed."""
    sent = []
    monkeypatch.setattr(
        "dhcpctl.backends._dnsmasq._signal_pidfile",
        lambda pidfile: sent.append(pidfile),
    )
    return sent


def test_dnsmasq_keep_takes_the_completion_next_server(tmp_path, installing):
    server, _, opts = _dnsmasq(tmp_path)
    server.add(installing(next_server="10.0.0.2"))
    assert (
        "tag:web01,option:bootfile-name,undionly.kpxe\n"
        "tag:web01,option:server-ip-address,10.0.0.2\n"
        in (opts / "web01.conf").read_text()
    )
    server.complete(installing(SANBOOT_ELSEWHERE, next_server="10.0.0.2"))
    after = (opts / "web01.conf").read_text()
    assert "tag:web01,option:bootfile-name,sanboot.ipxe\n" in after
    assert "tag:web01,option:server-ip-address,10.0.0.9\n" in after
    assert "server-ip-address,10.0.0.2\n" not in after


def test_dnsmasq_keep_bare_has_no_dhcp_boot(tmp_path, installing):
    server, _, opts = _dnsmasq(tmp_path)
    server.complete(installing({"keep": True}, next_server="10.0.0.2"))
    assert "option:bootfile-name" not in (opts / "web01.conf").read_text()


def test_dnsmasq_keep_rewrites_the_region(tmp_path, installing):
    server, hosts, opts = _dnsmasq(tmp_path)
    server.add(installing())
    before = "\n".join(p.read_text() for p in opts.iterdir())
    assert "undionly.kpxe" in before
    server.complete(installing(SANBOOT))
    after = "\n".join(p.read_text() for p in opts.iterdir())
    assert "sanboot.ipxe" in after and "undionly.kpxe" not in after
    # The host line stays, so the address is still reserved.
    assert any(p.read_text().strip() for p in hosts.iterdir())
