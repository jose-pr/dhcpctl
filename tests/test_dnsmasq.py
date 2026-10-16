"""The dnsmasq backend, against a real temporary tree and a recorded reload.

Nothing here talks to a dnsmasq: the files are the contract, so the tests read
them back whole rather than asserting on substrings.
"""

import importlib.util
import logging
import subprocess

import pytest

import dhcpctl
from dhcpctl.backends import DnsmasqBackend

#: What the scope implies for every client in it.
LAN = {"domain-name-servers": "10.0.0.53"}


def _dirs(tmp_path):
    hosts = tmp_path / "hosts.d"
    opts = tmp_path / "opts.d"
    hosts.mkdir()
    opts.mkdir()
    return hosts, opts


def _uri(hosts, opts, extra=""):
    return (
        f"dnsmasq:///?hostsfile={hosts.as_posix()}/&optsfile={opts.as_posix()}/{extra}"
    )


@pytest.fixture
def recorded(monkeypatch):
    """The reload commands run, instead of running them."""
    argvs = []
    monkeypatch.setattr(
        "dhcpctl.backends._dnsmasq._subprocess.run",
        lambda argv, **kw: argvs.append(argv),
    )
    return argvs


def test_connect_picks_the_dnsmasq_backend(tmp_path):
    hosts, opts = _dirs(tmp_path)
    assert isinstance(dhcpctl.connect(_uri(hosts, opts)), DnsmasqBackend)


def test_directory_mode_writes_one_file_per_client(tmp_path, reservation, caplog):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts, "&router=10.0.0.1"))
    r = reservation(
        server,
        {"boot-file-name": "pxelinux.0", "next-server": "10.0.0.2"},
        defaults=LAN,
    )
    with caplog.at_level(logging.INFO, logger="dhcpctl"):
        server.add(r)

    host_file = hosts / "web01.conf"
    assert host_file.read_text(encoding="utf-8") == (
        "dhcp-host=aa:bb:cc:dd:ee:ff,set:web01,10.0.0.10,web01\n"
    )
    written = (opts / "web01.conf").read_text(encoding="utf-8").splitlines()
    assert "dhcp-boot=tag:web01,pxelinux.0,,10.0.0.2" in written
    assert "dhcp-option=tag:web01,3,10.0.0.1" in written  # router
    assert "dhcp-option=tag:web01,6,10.0.0.53" in written  # dns
    # No reload configured and a directory: nothing to run, said once.
    assert "dhcp-hostsdir" in caplog.text


def test_the_reload_notice_is_logged_once(tmp_path, reservation, caplog):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    with caplog.at_level(logging.INFO, logger="dhcpctl"):
        server.add(reservation())
        server.add(reservation())
    assert caplog.text.count("dhcp-hostsdir") == 1


def test_a_client_without_ip_or_hostname_gets_a_mac_only_host_line(
    tmp_path, reservation
):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(ip=None, hostname=""))
    assert (hosts / "web01.conf").read_text(encoding="utf-8") == (
        "dhcp-host=aa:bb:cc:dd:ee:ff,set:web01\n"
    )


def test_the_tag_is_the_name_reduced_to_what_a_tag_may_hold(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(name="web 01.lan"))
    assert (hosts / "web-01-lan.conf").exists()


def test_removal_unlinks_and_is_quiet_the_second_time(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    r = reservation(server)
    server.add(r)
    assert (hosts / "web01.conf").exists()

    server.complete(r)
    assert not (hosts / "web01.conf").exists()
    assert not (opts / "web01.conf").exists()
    server.complete(r)  # must not raise


def test_file_mode_edits_only_its_own_region(tmp_path, reservation, recorded):
    hosts_file = tmp_path / "site.hosts"
    opts_file = tmp_path / "site.opts"
    hosts_file.write_text(
        "# written by hand\ndhcp-host=11:22:33:44:55:66,10.0.0.99,other\n# tail\n",
        encoding="utf-8",
    )
    opts_file.write_text("dhcp-option=99,hand-written\n", encoding="utf-8")
    uri = (
        f"dnsmasq:///?hostsfile={hosts_file.as_posix()}"
        f"&optsfile={opts_file.as_posix()}&reload=true"
    )
    server = dhcpctl.connect(uri)
    r = reservation(server)

    server.add(r)
    text = hosts_file.read_text(encoding="utf-8")
    assert (
        "# written by hand" in text and "10.0.0.99,other" in text and "# tail" in text
    )
    assert "# >>> dhcpctl web01" in text and "set:web01" in text
    assert "# <<< dhcpctl web01" in text

    server.complete(r)
    after = hosts_file.read_text(encoding="utf-8")
    assert "dhcpctl web01" not in after and "set:web01" not in after
    # Every foreign line survived add + remove, in order.
    assert after.splitlines() == [
        "# written by hand",
        "dhcp-host=11:22:33:44:55:66,10.0.0.99,other",
        "# tail",
    ]
    assert opts_file.read_text(encoding="utf-8") == "dhcp-option=99,hand-written\n"
    assert recorded == [["true"], ["true"]]


def test_file_mode_regions_are_named_by_the_owner(tmp_path, reservation, recorded):
    # Entries written under one owner are not found under another: a second
    # tool sharing the file cannot remove what this one wrote.
    hosts_file = tmp_path / "site.hosts"
    uri = f"dnsmasq:///?hostsfile={hosts_file.as_posix()}&reload=true"
    ours = dhcpctl.connect(uri)
    theirs = dhcpctl.connect(uri, owner="netboot")

    ours.add(reservation())
    theirs.add(reservation())
    text = hosts_file.read_text(encoding="utf-8")
    assert "# >>> dhcpctl web01" in text and "# >>> netboot web01" in text

    theirs.remove(reservation())
    lines = hosts_file.read_text(encoding="utf-8").splitlines()
    assert lines == [
        "# >>> dhcpctl web01",
        "dhcp-host=aa:bb:cc:dd:ee:ff,set:web01,10.0.0.10,web01",
        "# <<< dhcpctl web01",
    ]


def test_file_mode_without_a_reload_refuses(tmp_path, reservation):
    hosts_file = tmp_path / "site.hosts"
    hosts_file.write_text("", encoding="utf-8")
    server = dhcpctl.connect(f"dnsmasq:///?hostsfile={hosts_file.as_posix()}")
    with pytest.raises(dhcpctl.ConfigError, match="reload"):
        server.add(reservation())


def test_a_hostsfile_is_required():
    with pytest.raises(dhcpctl.ConfigError, match="hostsfile"):
        dhcpctl.connect("dnsmasq:///")


def _remote_is_local(monkeypatch, prefix):
    """Serve `<prefix><path>` from the local `<path>`.

    Stubs the path seam so a test needs no SSH server (and no sftp backend).
    """
    from dhcpctl._paths import parse_path as real_parse_path

    def fake_parse_path(value):
        text = str(value)
        if text.startswith(prefix):
            # Keep the leading separator: stripping it makes the path relative
            # to the working directory, which writes the reservation into the
            # checkout on POSIX.
            return real_parse_path(text[len(prefix) :])
        return real_parse_path(text)

    monkeypatch.setattr("dhcpctl.backends._dnsmasq.parse_path", fake_parse_path)
    # The remote seam is stubbed whole, so the "install the ssh extra" guard
    # (tested on its own below) must not fire here.
    monkeypatch.setattr("dhcpctl.backends._dnsmasq._require_sftp", lambda uri: None)


def test_a_remote_reload_runs_over_ssh(tmp_path, reservation, monkeypatch, recorded):
    # A URI with a host means remote paths; check what reload actually runs.
    hosts, opts = _dirs(tmp_path)
    _remote_is_local(monkeypatch, "sftp://admin@dhcp01")
    uri = (
        "dnsmasq://admin@dhcp01/?hostsfile="
        f"{hosts.as_posix()}/&optsfile={opts.as_posix()}/"
        "&reload=systemctl+reload+dnsmasq"
    )
    server = dhcpctl.connect(uri)
    server.add(reservation(server))
    assert recorded == [["ssh", "admin@dhcp01", "systemctl", "reload", "dnsmasq"]]
    assert (hosts / "web01.conf").exists()


def test_signal_is_refused_for_a_remote_dnsmasq(tmp_path, reservation, monkeypatch):
    hosts, _ = _dirs(tmp_path)
    _remote_is_local(monkeypatch, "sftp://dhcp01")
    server = dhcpctl.connect(
        f"dnsmasq://dhcp01/?hostsfile={hosts.as_posix()}/&reload=signal"
    )
    with pytest.raises(dhcpctl.ConfigError, match="local only"):
        server.add(reservation())


def test_a_remote_path_without_the_extra_names_it(monkeypatch):
    dhcpctl.get_backend("dnsmasq")  # imported before find_spec is stubbed
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a: None)
    with pytest.raises(dhcpctl.BackendUnavailableError, match=r"dhcpctl\[ssh\]"):
        dhcpctl.connect("dnsmasq://dhcp01/etc/dnsmasq.d/hosts.d/")


def test_a_remote_path_without_an_ssh_library_names_the_extra(monkeypatch):
    dhcpctl.get_backend("dnsmasq")
    real = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name, *a: None if name in ("paramiko", "asyncssh") else real(name, *a),
    )
    with pytest.raises(ImportError, match=r"dhcpctl\[ssh\]"):
        dhcpctl.connect("dnsmasq://dhcp01/etc/dnsmasq.d/hosts.d/")


def test_a_local_reload_runs_directly(tmp_path, reservation, recorded):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts, "&reload=systemctl+reload+dnsmasq"))
    server.add(reservation())
    assert recorded == [["systemctl", "reload", "dnsmasq"]]


def test_a_failing_reload_is_a_server_error(tmp_path, reservation, monkeypatch):
    hosts, opts = _dirs(tmp_path)

    def fail(argv, **kw):
        raise subprocess.CalledProcessError(3, argv)

    monkeypatch.setattr("dhcpctl.backends._dnsmasq._subprocess.run", fail)
    server = dhcpctl.connect(_uri(hosts, opts, "&reload=systemctl+reload+dnsmasq"))
    with pytest.raises(dhcpctl.ServerError, match=r"failed \(3\)"):
        server.add(reservation())


@pytest.mark.parametrize("mac", [None, "00:00:00:00:00:00"])
def test_a_client_without_a_mac_is_named(tmp_path, reservation, mac):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    with pytest.raises(dhcpctl.MissingMACError, match="nomac"):
        server.add(reservation(name="nomac", mac=mac))
    assert list(hosts.iterdir()) == []


def test_raw_lines_pass_through_untranslated(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(
        _uri(
            hosts, opts, "&raw.dnsmasq=dhcp-option%3Dtag%3Aweb01%2C252%2Chttp%3A%2F%2Fx"
        )
    )
    server.add(reservation(server))
    assert (
        "dhcp-option=tag:web01,252,http://x"
        in (opts / "web01.conf").read_text(encoding="utf-8").splitlines()
    )


def test_a_multi_valued_option_is_one_comma_joined_line(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(options={"domain-name-servers": ["10.0.0.53", "10.0.0.54"]}))
    written = (opts / "web01.conf").read_text(encoding="utf-8").splitlines()
    assert written == ["dhcp-option=tag:web01,6,10.0.0.53,10.0.0.54"]


def test_an_apply_time_key_in_the_uri_is_refused(tmp_path):
    hosts, opts = _dirs(tmp_path)
    with pytest.raises(dhcpctl.ConfigError, match="boot-file-name"):
        dhcpctl.connect(_uri(hosts, opts, "&boot-file-name=pxelinux.0"))


# -- extras ----------------------------------------------------------------

#: What dnsmasq is told, in its own language, to chainload iPXE.
IPXE_DNSMASQ = ("dhcp-match=set:ipxe,77,iPXE", "dhcp-boot=tag:ipxe,boot.ipxe")


def test_dnsmasq_writes_the_extra_lines_into_its_options_file(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    uri = _uri(hosts, opts, "&raw.dnsmasq=" + IPXE_DNSMASQ[0])
    server = dhcpctl.connect(uri)
    server.add(reservation(server, extras={"add": [IPXE_DNSMASQ[1]]}))
    written = (opts / "web01.conf").read_text(encoding="utf-8").splitlines()
    assert written[-2:] == list(IPXE_DNSMASQ)


def test_dnsmasq_keep_writes_the_remove_phase_extras(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts, "&raw.dnsmasq.remove=dhcp-option%3Dx"))
    r = reservation(
        server, {"boot-file-name": "undionly.kpxe"}, completion={"keep": True}
    )
    server.add(r)
    assert "dhcp-option=x" not in (opts / "web01.conf").read_text(encoding="utf-8")
    server.complete(r)
    written = (opts / "web01.conf").read_text(encoding="utf-8").splitlines()
    assert written == ["dhcp-option=x"]
