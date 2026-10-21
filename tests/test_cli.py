"""The `dhcpctl` command line, through its real parser."""

import json

import pytest

import dhcpctl

pytest.importorskip("duho", reason="needs the 'cli' extra")

from dhcpctl.cli import main  # noqa: E402

CLIENT = ["-n", "web01", "-m", "aa:bb:cc:dd:ee:ff", "--ip", "10.0.0.10"]


class _Memory(dhcpctl.DHCPServer):
    """Holds what it is told, and the secrets it was given."""

    held = {}

    def add(self, reservation):
        _Memory.held[reservation.target.name] = (reservation, self.secret("password"))

    def remove(self, reservation):
        _Memory.held.pop(reservation.target.name, None)

    def keep(self, reservation):
        _Memory.held[reservation.target.name] = (reservation, "kept")


@pytest.fixture
def memory():
    _Memory.held.clear()
    dhcpctl.register_backend("memory", _Memory)
    yield _Memory.held
    dhcpctl.unregister_backend("memory")


def test_render_prints_what_dhcpd_would_be_sent(capsys):
    argv = ["render", "dhcpd://dhcp01/", *CLIENT, "-o", "router=10.0.0.1"]
    argv += ["-o", "dns=10.0.0.53,10.0.0.54", "-o", "file=undionly.kpxe"]
    assert main(argv) == 0
    assert capsys.readouterr().out.splitlines() == [
        "del_host aa:bb:cc:dd:ee:ff",
        "create_host 10.0.0.10 aa:bb:cc:dd:ee:ff web01",
        "  statements: option routers 10.0.0.1; option domain-name-servers "
        '10.0.0.53, 10.0.0.54; filename "undionly.kpxe";',
    ]


def test_render_reads_a_reservation_document(tmp_path, capsys):
    document = tmp_path / "web01.json"
    reservation = {"target": {"name": "web01", "mac": "aa:bb:cc:dd:ee:ff"}}
    document.write_text(json.dumps(reservation), encoding="utf-8")
    assert (
        main(["render", "dhcpd://dhcp01/", "--from", str(document), "-a", "remove"])
        == 0
    )
    assert capsys.readouterr().out == "del_host aa:bb:cc:dd:ee:ff\n"


def test_add_complete_and_remove_reach_the_server(memory, capsys, monkeypatch):
    monkeypatch.setenv("DHCPCTL_PASSWORD", "s3cret")
    assert main(["add", "memory://m/", *CLIENT, "-o", "file=boot.ipxe"]) == 0
    reservation, password = memory["web01"]
    assert reservation.lease.file == "boot.ipxe" and password == "s3cret"
    assert main(["complete", "memory://m/", *CLIENT, "--keep"]) == 0
    assert memory["web01"][1] == "kept"
    assert main(["remove", "memory://m/", *CLIENT]) == 0
    assert memory == {}
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("armed web01 on memory://m/")
    assert out[1].startswith("kept web01") and out[2].startswith("removed web01")


def test_recipe_prints_each_conditions_setup(tmp_path, capsys):
    document = tmp_path / "web01.json"
    document.write_text(
        json.dumps(
            {
                "target": {"name": "web01", "mac": "aa:bb:cc:dd:ee:ff"},
                "conditions": {
                    "ipxe": {
                        "match": {"user-class": "iPXE"},
                        "options": {"file": "boot.ipxe"},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    assert main(["recipe", "dhcpd://dhcp01/", "--from", str(document)]) == 0
    assert 'group "ipxe" {' in capsys.readouterr().out


def test_backends_lists_every_scheme_as_json(capsys):
    assert main(["backends", "--json"]) == 0
    schemes = {row["scheme"] for row in json.loads(capsys.readouterr().out)}
    assert {"dnsmasq", "kea", "dhcpd", "windhcp"} <= schemes


def test_a_wrong_invocation_is_status_2_and_a_refusal_status_1(
    memory, capsys, monkeypatch
):
    assert main(["render", "dhcpd://dhcp01/", "-m", "aa:bb:cc:dd:ee:ff"]) == 2
    assert main(["render", "nosuch://x/", *CLIENT]) == 2

    def refuse(self, reservation):
        raise dhcpctl.ServerError("no room")

    monkeypatch.setattr(_Memory, "add", refuse)
    assert main(["add", "memory://m/", *CLIENT]) == 1
    assert "no room" in capsys.readouterr().err


def test_an_option_value_can_be_json():
    from dhcpctl.cli._common import parse_option

    assert parse_option("lease-time=json:600") == ("lease-time", 600)
    assert parse_option("dns=a, b") == ("dns", ["a", "b"])
    assert parse_option("file=x") == ("file", "x")


def test_help_and_a_usage_error_still_raise_system_exit(capsys):
    with pytest.raises(SystemExit) as shown:
        main(["--help"])
    assert shown.value.code == 0
    with pytest.raises(SystemExit) as shown:
        main(["render"])
    assert shown.value.code == 2


def test_ctrl_c_is_status_130_and_a_closed_pipe_status_1(monkeypatch):
    from dhcpctl.cli.render import Render

    def interrupted(self):
        raise KeyboardInterrupt

    def closed(self):
        raise BrokenPipeError

    argv = ["render", "dhcpd://dhcp01/", *CLIENT]
    monkeypatch.setattr(Render, "__call__", interrupted)
    assert main(argv) == 130
    monkeypatch.setattr(Render, "__call__", closed)
    assert main(argv) == 1
