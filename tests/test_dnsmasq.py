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
LAN = {"dns": "10.0.0.53"}


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


class _Recorded(list):
    """Each reload's argv, prefixed with `ssh <user@host>` when it ran remotely."""

    error = None


@pytest.fixture
def recorded(monkeypatch):
    """The reload commands hostctl would run, instead of running them."""
    import hostctl

    argvs = _Recorded()

    class _Host:
        def __init__(self, config):
            self.config = config

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def run(self, command, **kwargs):
            argv = [command.program, *command.args]
            if isinstance(self.config, hostctl.SSHConfig):
                user = f"{self.config.username}@" if self.config.username else ""
                argv = ["ssh", f"{user}{self.config.host}", *argv]
            argvs.append(argv)
            if argvs.error is not None:
                raise argvs.error

    monkeypatch.setattr("dhcpctl.backends._dnsmasq._open_host", _Host)
    return argvs


@pytest.fixture
def hups(monkeypatch):
    """The pidfiles SIGHUPed, instead of signalling anything."""
    sent = []
    monkeypatch.setattr(
        "dhcpctl.backends._dnsmasq._signal_pidfile",
        lambda pidfile: sent.append(pidfile),
    )
    return sent


def test_connect_picks_the_dnsmasq_backend(tmp_path):
    hosts, opts = _dirs(tmp_path)
    assert isinstance(dhcpctl.connect(_uri(hosts, opts)), DnsmasqBackend)


def test_directory_mode_writes_one_file_per_client(tmp_path, reservation, caplog):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    r = reservation(
        server,
        {"file": "pxelinux.0"},
        defaults={**LAN, "router": "10.0.0.1"},
        next_server="10.0.0.2",
    )
    with caplog.at_level(logging.INFO, logger="dhcpctl"):
        server.add(r)

    host_file = hosts / "web01.conf"
    assert host_file.read_text(encoding="utf-8") == (
        "aa:bb:cc:dd:ee:ff,set:web01,10.0.0.10,web01\n"
    )
    written = (opts / "web01.conf").read_text(encoding="utf-8").splitlines()
    assert "tag:web01,option:bootfile-name,pxelinux.0" in written
    assert "tag:web01,option:server-ip-address,10.0.0.2" in written
    assert "tag:web01,3,10.0.0.1" in written  # router
    assert "tag:web01,6,10.0.0.53" in written  # dns
    assert "dhcp-" not in written, "an options file holds values, not keys"
    # No reload configured and a directory: nothing to run, said once.
    assert "dhcp-hostsdir" in caplog.text


@pytest.mark.parametrize(
    "options, next_server, line",
    [
        ({"file": "pxelinux.0"}, None, "tag:web01,option:bootfile-name,pxelinux.0"),
        ({}, "10.0.0.2", "tag:web01,option:server-ip-address,10.0.0.2"),
    ],
)
def test_next_server_is_the_third_dhcp_boot_field(
    tmp_path, reservation, options, next_server, line
):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(server, options, next_server=next_server))
    written = (opts / "web01.conf").read_text(encoding="utf-8").splitlines()
    assert written == [line]


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
        "aa:bb:cc:dd:ee:ff,set:web01\n"
    )


@pytest.mark.parametrize("unset", [None, "0.0.0.0"])
def test_an_unspecified_address_is_never_written(tmp_path, reservation, unset):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(options={"file": "pxelinux.0"}, ip=unset, next_server=unset))
    assert (hosts / "web01.conf").read_text(encoding="utf-8") == (
        "aa:bb:cc:dd:ee:ff,set:web01,web01\n"
    )
    assert (opts / "web01.conf").read_text(encoding="utf-8") == (
        "tag:web01,option:bootfile-name,pxelinux.0\n"
    )


def test_an_unspecified_next_server_alone_writes_no_dhcp_boot(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(options={"dns": "10.0.0.53"}, next_server="0.0.0.0"))
    assert (opts / "web01.conf").read_text(encoding="utf-8") == (
        "tag:web01,6,10.0.0.53\n"
    )


def test_the_tag_is_the_name_reduced_to_what_a_tag_may_hold(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(name="web 01.lan"))
    (written,) = hosts.iterdir()
    assert written.name.startswith("web-01-lan-") and written.suffix == ".conf"


def test_names_that_reduce_alike_are_two_tags(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(name="web.01"))
    server.add(reservation(name="web-01"))
    names = sorted(p.name for p in hosts.iterdir())
    assert len(names) == 2 and "web-01.conf" in names


def test_removal_unlinks_and_is_quiet_the_second_time(tmp_path, reservation, hups):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    r = reservation(server)
    server.add(r)
    assert (hosts / "web01.conf").exists()
    assert hups == [], "a new file is read without a signal"

    server.complete(r)
    assert not (hosts / "web01.conf").exists()
    assert not (opts / "web01.conf").exists()
    # dnsmasq keeps serving a deleted hostsdir file until SIGHUP.
    assert hups == ["/run/dnsmasq/dnsmasq.pid"]
    server.complete(r)  # must not raise
    assert len(hups) == 1, "nothing was taken away the second time"


def test_rearming_with_other_options_signals(tmp_path, reservation, hups):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts, "&pidfile=/run/x.pid"))
    server.add(reservation(server, {"file": "a.efi"}))
    server.add(reservation(server, {"file": "a.efi"}))
    assert hups == [], "the same entry again changes nothing dnsmasq read"
    server.add(reservation(server, {"file": "b.efi"}))
    assert hups == ["/run/x.pid"]


def test_a_remote_directory_needs_a_reload_command_to_take_entries_away(
    monkeypatch, reservation
):
    pytest.importorskip("sftppath", reason="a remote path needs the 'ssh' extra")
    server = dhcpctl.connect("dnsmasq://dns01/?hostsfile=/etc/dnsmasq.d/hosts/")
    monkeypatch.setattr(server, "_write", lambda which, tag, lines: True)
    with pytest.raises(dhcpctl.ConfigError, match="reload=<command>"):
        server.remove(reservation(server))


def test_options_with_no_optsfile_are_refused(tmp_path, reservation):
    hosts, _ = _dirs(tmp_path)
    server = dhcpctl.connect(f"dnsmasq:///?hostsfile={hosts.as_posix()}/")
    with pytest.raises(dhcpctl.ConfigError, match="no optsfile"):
        server.add(reservation(server, {"file": "undionly.kpxe"}))
    assert list(hosts.iterdir()) == [], "nothing is written for a refused client"
    server.add(reservation(server))  # a client served nothing needs no optsfile


def test_a_trailing_slash_means_a_directory_before_it_exists(tmp_path, reservation):
    hosts, opts = tmp_path / "new" / "hosts", tmp_path / "new" / "opts"
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(server, {"file": "a.efi"}))
    assert (hosts / "web01.conf").is_file() and (opts / "web01.conf").is_file()


def test_a_failing_or_missing_reload_command_is_a_server_error(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts, "&reload=no-such-reload-program-x"))
    with pytest.raises(dhcpctl.ServerError, match="cannot run reload command"):
        server.add(reservation(server))


def test_a_pidfile_that_cannot_be_read_is_a_server_error(tmp_path):
    from dhcpctl.backends._dnsmasq import _signal_pidfile
    import signal

    if not hasattr(signal, "SIGHUP"):
        with pytest.raises(dhcpctl.ConfigError, match="no SIGHUP"):
            _signal_pidfile(str(tmp_path / "none.pid"))
        return
    with pytest.raises(dhcpctl.ServerError, match="cannot SIGHUP"):
        _signal_pidfile(str(tmp_path / "none.pid"))


def test_file_mode_edits_only_its_own_region(tmp_path, reservation, recorded):
    hosts_file = tmp_path / "site.hosts"
    opts_file = tmp_path / "site.opts"
    hosts_file.write_text(
        "# written by hand\n11:22:33:44:55:66,10.0.0.99,other\n# tail\n",
        encoding="utf-8",
    )
    opts_file.write_text("99,hand-written\n", encoding="utf-8")
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
        "11:22:33:44:55:66,10.0.0.99,other",
        "# tail",
    ]
    assert opts_file.read_text(encoding="utf-8") == "99,hand-written\n"
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
        "aa:bb:cc:dd:ee:ff,set:web01,10.0.0.10,web01",
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


@pytest.mark.parametrize(
    "error, message",
    [
        (subprocess.CalledProcessError(3, "x"), r"failed \(3\)"),
        (subprocess.TimeoutExpired("x", 60), "did not finish in 60 seconds"),
        (FileNotFoundError("no such program"), "cannot run reload command"),
    ],
)
def test_a_failing_reload_is_a_server_error(
    tmp_path, reservation, recorded, error, message
):
    hosts, opts = _dirs(tmp_path)
    recorded.error = error
    server = dhcpctl.connect(_uri(hosts, opts, "&reload=systemctl+reload+dnsmasq"))
    with pytest.raises(dhcpctl.ServerError, match=message):
        server.add(reservation())


@pytest.mark.parametrize("mac", [None, "00:00:00:00:00:00"])
def test_a_client_without_a_mac_is_named(tmp_path, reservation, mac):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    with pytest.raises(dhcpctl.MissingMACError, match="nomac"):
        server.add(reservation(name="nomac", mac=mac))
    assert list(hosts.iterdir()) == []


def test_extra_lines_pass_through_untranslated(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(server, extras={"add": ["tag:web01,252,http://x"]}))
    assert (
        "tag:web01,252,http://x"
        in (opts / "web01.conf").read_text(encoding="utf-8").splitlines()
    )


def test_a_multi_valued_option_is_one_comma_joined_line(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(options={"dns": ["10.0.0.53", "10.0.0.54"]}))
    written = (opts / "web01.conf").read_text(encoding="utf-8").splitlines()
    assert written == ["tag:web01,6,10.0.0.53,10.0.0.54"]


# -- extras ----------------------------------------------------------------

#: What dnsmasq is told, in its own language, to chainload iPXE.
IPXE_DNSMASQ = (
    "dhcp-match=set:ipxe,77,iPXE",
    "dhcp-option=tag:ipxe,option:bootfile-name,boot.ipxe",
)


def test_dnsmasq_writes_the_extra_lines_into_its_options_file(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(server, extras={"add": list(IPXE_DNSMASQ)}))
    written = (opts / "web01.conf").read_text(encoding="utf-8").splitlines()
    assert written[-2:] == list(IPXE_DNSMASQ)


def test_dnsmasq_keep_writes_the_remove_phase_extras(tmp_path, reservation, hups):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    r = reservation(
        server,
        {"file": "undionly.kpxe"},
        completion={"keep": True},
        extras={"remove": ["dhcp-option=x"]},
    )
    server.add(r)
    assert "dhcp-option=x" not in (opts / "web01.conf").read_text(encoding="utf-8")
    server.complete(r)
    written = (opts / "web01.conf").read_text(encoding="utf-8").splitlines()
    assert written == ["dhcp-option=x"]


def test_option_67_is_a_dhcp_option_not_dhcp_boot(tmp_path, reservation):
    hosts, opts = _dirs(tmp_path)
    server = dhcpctl.connect(_uri(hosts, opts))
    server.add(reservation(options={"bootfile-name": "a.efi", "sname": "tftp01"}))
    assert (opts / "web01.conf").read_text(encoding="utf-8").splitlines() == [
        "tag:web01,option:tftp-server,tftp01",
        "tag:web01,67,a.efi",
    ]


@pytest.mark.parametrize(
    "options, line",
    [
        ({"option-224": "0a0b"}, "tag:web01,224,0a:0b"),
        ({"option-224": "0a"}, "tag:web01,224,10"),  # alone, `0a` is text
        ({"ip-forwarding": True}, "tag:web01,19,1"),
        ({"time-offset": -3600}, "tag:web01,2,ff:ff:f1:f0"),
        ({"mtu-plateau": [576, 1500]}, "tag:web01,25,02:40:05:dc"),
        ({"router": ["10.0.0.1", "10.0.0.2"]}, "tag:web01,3,10.0.0.1,10.0.0.2"),
        ({"domain-name": "example.com"}, "tag:web01,15,example.com"),
    ],
)
def test_each_value_is_written_as_dnsmasq_reads_it(options, line):
    from dhcpctl.backends._dnsmasq import _option_lines

    assert _option_lines("web01", dhcpctl.PYDHCP_CODES.lease(options)) == [line]


_WRITER = """
import sys
import dhcpctl
from netimps import MACAddress

server = dhcpctl.connect(sys.argv[1])
for n in range(int(sys.argv[3])):
    name = f"{sys.argv[2]}{n}"
    mac = MACAddress(f"aa:bb:cc:{sys.argv[2] == 'a' and 1 or 2:02x}:00:{n:02x}")
    server.add(dhcpctl.Reservation(dhcpctl.Target(name, mac=mac)))
"""


def test_two_writers_of_one_hosts_file_keep_each_others_entries(tmp_path):
    import subprocess
    import sys

    hosts = tmp_path / "hosts"
    uri = f"dnsmasq:///?hostsfile={hosts.as_posix()}&reload=true"
    script = tmp_path / "writer.py"
    script.write_text(_WRITER, encoding="utf-8")
    writers = [
        subprocess.Popen([sys.executable, str(script), uri, prefix, "25"])
        for prefix in ("a", "b")
    ]
    assert [writer.wait(timeout=120) for writer in writers] == [0, 0]
    text = hosts.read_text(encoding="utf-8")
    lines = set(text.splitlines())
    missing = [f"{p}{n}" for p in "ab" for n in range(25)]
    missing = [
        name
        for name in missing
        if not any(line.endswith(f",set:{name}") for line in lines)
    ]
    assert missing == []
