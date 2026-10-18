"""`DHCPServer.render`: what an operation would send, with nothing contacted."""

import json

import pytest

import dhcpctl

IPXE = {"ipxe": {"match": {"user-class": "iPXE"}, "options": {"file": "boot.ipxe"}}}


@pytest.fixture
def lan(reservation):
    def build(**kwargs):
        kwargs.setdefault("options", {"router": "10.0.0.1", "file": "undionly.kpxe"})
        kwargs.setdefault("subnet_id", 1)
        return reservation(**kwargs)

    return build


def _nothing_sent(monkeypatch):
    """Fail on any transport, so rendering is shown to contact nothing."""
    import requests

    def refuse(*args, **kwargs):
        raise AssertionError("render contacted the server")

    monkeypatch.setattr(requests, "post", refuse)
    from dhcpctl.backends import _windhcp

    monkeypatch.setattr(_windhcp, "_open_host", refuse)


def test_dnsmasq_renders_the_entry_under_its_path_and_the_reload(lan, monkeypatch):
    server = dhcpctl.connect(
        "dnsmasq:///?hostsfile=/etc/d/hosts/&optsfile=/etc/d/opts&reload=reload-it"
    )
    text = server.render(lan())
    assert text.splitlines() == [
        "# hosts: /etc/d/hosts/web01.conf",
        "aa:bb:cc:dd:ee:ff,set:web01,10.0.0.10,web01",
        "# opts: /etc/d/opts [web01]",
        "tag:web01,option:bootfile-name,undionly.kpxe",
        "tag:web01,3,10.0.0.1",
        "# reload: reload-it",
    ]
    assert "removed" in server.render(lan(), "remove")


def test_kea_renders_each_command_body(lan, monkeypatch):
    _nothing_sent(monkeypatch)
    server = dhcpctl.connect("kea://kea01/")
    text, bodies, decoder = (
        server.render(lan(conditions=IPXE)).strip(),
        [],
        json.JSONDecoder(),
    )
    while text:
        body, end = decoder.raw_decode(text)
        bodies.append(body)
        text = text[end:].strip()
    assert [body["command"] for body in bodies] == [
        "class-add",
        "class-add",
        "reservation-add",
    ]


def test_kea_needs_the_subnet_id_to_render(lan, monkeypatch):
    _nothing_sent(monkeypatch)
    with pytest.raises(dhcpctl.ConfigError, match="subnet id"):
        dhcpctl.connect("kea://kea01/").render(lan(subnet_id=None))


def test_dhcpd_renders_the_omapi_calls(lan):
    text = dhcpctl.connect("dhcpd://dhcp01/").render(lan())
    assert text.splitlines() == [
        "del_host aa:bb:cc:dd:ee:ff",
        "create_host 10.0.0.10 aa:bb:cc:dd:ee:ff web01",
        '  statements: option routers 10.0.0.1; filename "undionly.kpxe";',
    ]


def test_windhcp_renders_the_script_the_shell_would_run(lan, monkeypatch):
    _nothing_sent(monkeypatch)
    text = dhcpctl.connect("windhcp://dhcp01/?transport=winrm").render(lan())
    assert "Add-DhcpServerv4Reservation" in text and "ConvertFrom-Json" in text


def test_rendering_leaves_the_server_usable(lan):
    server = dhcpctl.connect("dhcpd://dhcp01/")
    server.render(lan())
    assert "omapi" not in vars(server)


def test_an_unknown_action_and_a_backend_without_a_recorder_are_refused(lan):
    with pytest.raises(ValueError, match="action"):
        dhcpctl.connect("dhcpd://dhcp01/").render(lan(), "nuke")

    class Plain(dhcpctl.DHCPServer):
        def add(self, reservation):
            raise AssertionError("must not run")

    with pytest.raises(NotImplementedError, match="Plain cannot render"):
        Plain("plain://x").render(lan())
