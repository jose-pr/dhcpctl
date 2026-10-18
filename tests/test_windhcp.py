"""The Windows DHCP backend, against a stub transport.

The script is the contract here, so the tests read the generated PowerShell and
the JSON payload inside it -- including with values that try to break out of it.
"""

import json
import subprocess

import pytest

import dhcpctl
from dhcpctl.backends import WinDHCPBackend

#: What the scope implies for every client in it.
LAN = {"router": "10.0.0.1"}


@pytest.fixture
def stub(monkeypatch):
    """A backend whose transport records the script instead of running it."""

    def build(uri="windhcp://admin@dhcp01/", **kwargs):
        server = dhcpctl.connect(uri, **kwargs)
        ran = []
        monkeypatch.setattr(
            server,
            "run",
            lambda payload, body: ran.append(server.script_for(payload, body)),
        )
        return server, ran

    return build


@pytest.fixture
def lan(reservation):
    """`web01` with the scope's router."""

    def build(*args, **kwargs):
        kwargs.setdefault("defaults", LAN)
        return reservation(*args, **kwargs)

    return build


def _payload(script: str) -> dict:
    """Parse back what PowerShell would parse: the single-quoted JSON literal."""
    start = script.index("ConvertFrom-Json '") + len("ConvertFrom-Json '")
    end = script.index("'\n", start)
    return json.loads(script[start:end].replace("''", "'"))


class _Completed:
    def __init__(self, returncode=0, stdout='{"ok": true}', stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def hosts(monkeypatch):
    """hostctl hosts the backend opens, recorded: each `(config, script)`.

    `hosts.result` is what every run returns; set `hosts.error` to raise it.
    """

    class _Hosts(list):
        result = _Completed()
        error = None

    opened = _Hosts()

    class _Host:
        def __init__(self, config):
            self.config = config

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def run(self, script, **kwargs):
            opened.append((self.config, script))
            if opened.error is not None:
                raise opened.error
            return opened.result

    monkeypatch.setattr("dhcpctl.backends._windhcp._open_host", _Host)
    return opened


def test_connect_picks_the_windhcp_backend():
    assert isinstance(dhcpctl.connect("windhcp://dhcp01/"), WinDHCPBackend)


def test_add_builds_the_reservation_and_its_options(stub, lan):
    server, ran = stub()
    server.add(
        lan(
            server,
            {
                "bootfile-name": "boot\\x64\\wdsnbp.com",
                "tftp-server": "10.0.0.2",
            },
            defaults={**LAN, "dns": "10.0.0.53"},
        )
    )

    script = ran[0]
    assert "Add-DhcpServerv4Reservation" in script
    assert "Set-DhcpServerv4OptionValue" in script
    payload = _payload(script)
    assert payload["ScopeId"] == "10.0.0.0"  # from the scope's network
    assert payload["IPAddress"] == "10.0.0.10"
    assert payload["ClientId"] == "aa-bb-cc-dd-ee-ff"  # Windows' hyphen spelling
    assert payload["Name"] == "web01"
    ids = {option["Id"]: option["Value"] for option in payload["Options"]}
    # A one-element list: -Value takes String[], never a joined string.
    assert ids[67] == ["boot\\x64\\wdsnbp.com"]  # boot file
    assert ids[66] == ["10.0.0.2"]  # tftp server
    assert ids[6] == ["10.0.0.53"]
    assert ids[3] == ["10.0.0.1"]  # router, from the scope


def test_computer_name_is_only_sent_when_it_differs(stub, lan):
    server, ran = stub("windhcp://admin@jump/?server=dhcp01")
    server.add(lan())
    assert _payload(ran[0])["ComputerName"] == "dhcp01"

    plain, ran_plain = stub("windhcp://admin@dhcp01/")
    plain.add(lan())
    assert _payload(ran_plain[0])["ComputerName"] == ""


@pytest.mark.parametrize(
    "hostile",
    [
        "'; Remove-Item C:\\ -Recurse; #",
        "quote'inside",
        'double"quote',
        "line\nbreak",
    ],
)
def test_a_hostile_value_stays_data(stub, lan, hostile):
    # The whole design: values are parsed as JSON by PowerShell, never spliced
    # into the script, so a value cannot become a statement.
    server, ran = stub()
    server.add(lan(name=hostile))
    script = ran[0]

    payload = _payload(script)
    assert payload["Name"] == hostile
    # Every single quote inside the literal is doubled -- the one escaping rule.
    literal = script[
        script.index("ConvertFrom-Json '")
        + len("ConvertFrom-Json '") : script.index("'\n")
    ]
    assert "'" not in literal.replace("''", "")
    # And the script still has exactly one JSON literal to parse.
    assert script.count("ConvertFrom-Json") == 1


def test_remove_checks_before_removing(stub, lan):
    server, ran = stub()
    server.remove(lan())
    script = ran[0]
    assert "Get-DhcpServerv4Reservation" in script
    assert "Remove-DhcpServerv4Reservation" in script
    payload = _payload(script)
    assert payload["ClientId"] == "aa-bb-cc-dd-ee-ff"
    assert "IPAddress" not in payload


def test_the_scope_id_overrides_the_network(stub, lan):
    server, ran = stub()
    server.add(lan(scope_id="10.99.0.0"))
    assert _payload(ran[0])["ScopeId"] == "10.99.0.0"


def test_a_scope_with_neither_network_nor_id_is_refused(stub, lan):
    server, ran = stub()
    with pytest.raises(dhcpctl.ConfigError, match="network address"):
        server.add(lan(network=None))
    assert ran == []


def test_ssh_is_the_default_transport_through_hostctl(hosts, lan):
    import hostctl
    from hostctl.shell import POWERSHELL

    server = dhcpctl.connect("windhcp://admin@dhcp01/?port=2222")
    assert server.transport == "ssh"
    server.add(lan())
    ((config, script),) = hosts
    assert isinstance(config, hostctl.SSHConfig)
    assert (config.host, config.port, config.username) == ("dhcp01", 2222, "admin")
    assert config.shell is POWERSHELL
    assert "Add-DhcpServerv4Reservation" in script


def test_the_user_secret_fills_in_for_a_uri_without_one(hosts, lan):
    server = dhcpctl.connect("windhcp://dhcp01/", secrets={"user": "svc-dhcp"})
    assert server.user == "svc-dhcp"
    server.add(lan())
    assert hosts[0][0].username == "svc-dhcp"


def test_the_secret_user_overrides_the_uris():
    server = dhcpctl.connect("windhcp://admin@dhcp01/", secrets={"user": "svc"})
    assert server.user == "svc"
    assert dhcpctl.connect("windhcp://admin@dhcp01/").user == "admin"


def test_a_failing_run_raises_with_the_error(hosts, lan):
    hosts.result = _Completed(1, "", "Add-DhcpServerv4Reservation : Access is denied")
    server = dhcpctl.connect("windhcp://admin@dhcp01/")
    with pytest.raises(dhcpctl.ServerError, match="failed \\(1\\).*Access is denied"):
        server.add(lan())


@pytest.mark.parametrize(
    "error, message",
    [
        (ConnectionRefusedError("refused"), "cannot reach.*refused"),
        (PermissionError("denied"), "cannot reach.*denied"),
        (subprocess.TimeoutExpired("x", 120), "did not finish in 120 seconds"),
    ],
)
def test_a_transport_failure_is_a_server_error(hosts, lan, error, message):
    hosts.error = error
    server = dhcpctl.connect("windhcp://admin@dhcp01/")
    with pytest.raises(dhcpctl.ServerError, match=message):
        server.add(lan())


def test_the_timeout_setting_bounds_a_script(hosts, lan):
    server = dhcpctl.connect("windhcp://admin@dhcp01/?timeout=30")
    server.add(lan())
    assert hosts[0][0].timeout.total == 30


# -- transport=winrm --------------------------------------------------------


def test_winrm_runs_the_script_with_the_password_secret(hosts, lan):
    import hostctl

    server = dhcpctl.connect(
        "windhcp://admin@dhcp01/?transport=winrm", secrets={"password": "pw"}
    )
    server.add(lan())
    ((config, script),) = hosts
    assert isinstance(config, hostctl.WinRMConfig)
    assert (config.host, config.username, config.auth) == ("dhcp01", "admin", "ntlm")
    assert config.password == "pw" and not config.tls
    assert "Add-DhcpServerv4Reservation" in script


def test_winrm_over_tls_with_another_auth(hosts, lan):
    server = dhcpctl.connect(
        "windhcp://admin@dhcp01/?transport=winrm&ssl=true&port=5986&auth=kerberos"
    )
    server.add(lan())
    config = hosts[0][0]
    assert (config.port, config.tls, config.auth) == (5986, True, "kerberos")


def test_a_missing_transport_extra_names_dhcpctls(hosts, lan):
    from hostctl import MissingExtraError

    hosts.error = MissingExtraError("winrm", "WinRM command execution")
    server = dhcpctl.connect("windhcp://admin@dhcp01/?transport=winrm")
    with pytest.raises(dhcpctl.BackendUnavailableError, match=r"pydhcpctl\[winrm\]"):
        server.add(lan())


def test_an_unknown_transport_is_refused():
    with pytest.raises(dhcpctl.ConfigError, match="local, ssh or winrm"):
        dhcpctl.connect("windhcp://admin@dhcp01/?transport=telnet")


@pytest.mark.parametrize("mac", [None, "00:00:00:00:00:00"])
def test_a_client_without_a_mac_is_named(stub, lan, mac):
    server, ran = stub()
    with pytest.raises(dhcpctl.MissingMACError, match="nomac"):
        server.add(lan(name="nomac", mac=mac))
    assert ran == []


# -- method=netsh -----------------------------------------------------------


def _commands(script: str) -> "list[list[str]]":
    """The netsh argument lists the script would run, in order."""
    return [c["Args"] for c in _payload(script)["Commands"]]


def test_the_default_method_is_the_powershell_cmdlets(stub, lan):
    server, ran = stub()
    assert server.method == "powershell"
    server.add(lan())
    assert "Add-DhcpServerv4Reservation" in ran[0]
    assert "netsh" not in ran[0]


def test_an_unknown_method_is_refused():
    with pytest.raises(dhcpctl.ConfigError, match="method must be"):
        dhcpctl.connect("windhcp://dhcp01/?method=wmic")


@pytest.mark.parametrize("owner", ["dhcpctl", "netboot"])
def test_netsh_adds_the_reservation_then_its_options(stub, lan, owner):
    server, ran = stub("windhcp://admin@dhcp01/?method=netsh", owner=owner)
    server.add(
        lan(options={"bootfile-name": "pxelinux.0", "ip-address-lease-time": 600})
    )
    commands = _commands(ran[0])
    # Re-arming replaces the client's reservation: deleting one that is not
    # there is not an error.
    assert commands[0][4:] == ["delete", "reservedip", "10.0.0.10", "aabbccddeeff"]
    commands = commands[1:]
    # The reservation first -- an option on a reservation that does not exist
    # yet is an error, so order is part of the contract.
    assert commands[0] == [
        "dhcp",
        "server",
        "scope",
        "10.0.0.0",
        "add",
        "reservedip",
        "10.0.0.10",
        "aabbccddeeff",  # netsh wants bare hex, not the cmdlets' hyphens
        "web01",
        owner,  # the reservation's comment says who wrote it
        "BOTH",
    ]
    rest = {tuple(c[4:]) for c in commands[1:]}
    assert (
        "set",
        "reservedoptionvalue",
        "10.0.0.10",
        "3",
        "IPADDRESS",
        "10.0.0.1",
    ) in rest
    assert (
        "set",
        "reservedoptionvalue",
        "10.0.0.10",
        "67",
        "STRING",
        "pxelinux.0",
    ) in rest
    assert ("set", "reservedoptionvalue", "10.0.0.10", "51", "DWORD", "600") in rest


def test_netsh_passes_an_unknown_option_as_a_string(stub, lan):
    server, ran = stub("windhcp://dhcp01/?method=netsh")
    server.add(lan(options={"option-252": "http://proxy/wpad.dat"}))
    wpad = [c for c in _commands(ran[0]) if "252" in c][0]
    assert wpad[-2:] == ["STRING", "http://proxy/wpad.dat"]


def test_netsh_is_told_a_declared_options_type_from_the_codemap(stub, lan):
    codes = dhcpctl.option_codes({"x": {"code": 224, "type": "U32"}})
    server, ran = stub("windhcp://dhcp01/?method=netsh", codes=codes)
    server.add(lan(server, {"x": 4096}))
    option = [c for c in _commands(ran[0]) if "224" in c][0]
    assert option[-3:] == ["224", "DWORD", "4096"]
    # The type is the codemap's: pydhcp's codemap still calls 224 opaque.
    from dhcpctl.backends._windhcp import _netsh_type

    assert _netsh_type(dhcpctl.PYDHCP_CODES.resolve(224)) == "STRING"


def test_netsh_passes_a_multi_valued_option_as_separate_arguments(stub, reservation):
    # The cmdlets take a list, netsh takes one argument per value. Joining for
    # either would send "a,b" as a single address.
    server, ran = stub("windhcp://dhcp01/?method=netsh")
    server.add(reservation(options={"dns": ["10.0.0.53", "10.0.0.54"]}))
    dns = [c for c in _commands(ran[0]) if "6" in c and "IPADDRESS" in c][0]
    assert dns[-2:] == ["10.0.0.53", "10.0.0.54"]


def test_the_cmdlets_get_a_list_of_values_not_a_joined_string(stub, lan):
    # Measured against Windows Server 2025: `Set-DhcpServerv4OptionValue -Value`
    # takes String[] and refuses "a,b" with "Parameters for option value ... do
    # not match with option definition", which under ErrorAction Stop also
    # abandons every option after it. A reservation then has a router and no
    # boot file, which is a client that gets an address and cannot boot.
    server, ran = stub("windhcp://dhcp01/")
    server.add(lan(options={"dns": ["10.0.0.53", "10.0.0.54"]}))
    options = {o["Id"]: o["Value"] for o in _payload(ran[0])["Options"]}
    assert options[6] == ["10.0.0.53", "10.0.0.54"]
    # A single-valued option is still a one-element list, so the script needs no
    # special case.
    assert options[3] == ["10.0.0.1"]


def test_netsh_addresses_a_remote_server_unc_style(stub, lan):
    server, ran = stub("windhcp://dhcp01/?method=netsh&server=dhcp02")
    server.add(lan())
    assert _commands(ran[0])[0][:3] == ["dhcp", "server", "\\\\dhcp02"]


def test_a_server_already_written_unc_style_is_not_doubled(stub, lan):
    server, ran = stub("windhcp://dhcp01/?method=netsh&server=" + "%5C%5Cdhcp02")
    assert server.server == "\\\\dhcp02"
    server.add(lan())
    assert _commands(ran[0])[0][2] == "\\\\dhcp02"


def test_netsh_removal_tolerates_a_missing_reservation(stub, lan):
    server, ran = stub("windhcp://dhcp01/?method=netsh")
    server.remove(lan())
    payload = _payload(ran[0])
    assert payload["Commands"][0]["Args"][4:] == [
        "delete",
        "reservedip",
        "10.0.0.10",
        "aabbccddeeff",
    ]
    # Cleanup re-runs, so deleting nothing is success.
    assert payload["Commands"][0]["Ignore"] is True


def test_netsh_arguments_are_passed_as_an_array_not_a_command_line(stub, lan):
    # The whole reason netsh is driven from PowerShell: an argument stays an
    # array element, so no value can become syntax.
    server, ran = stub("windhcp://dhcp01/?method=netsh")
    server.add(lan())
    # `@a` on a variable splats; `@($c.Args)` would pass one array argument.
    assert "$a = @($c.Args)" in ran[0] and "& netsh @a" in ran[0]
    # Nothing is spliced into the script: the only quote-bearing text is JSON.
    assert "$LASTEXITCODE" in ran[0]


def test_a_hostile_value_stays_inside_the_json_payload(stub, lan):
    hostile = "web01'; Remove-Item C:\\ -Recurse #"
    server, ran = stub("windhcp://dhcp01/?method=netsh")
    server.add(lan(name=hostile))
    script = ran[0]
    # It survives as data, exactly as given, and never as script text.
    assert _commands(script)[1][-3] == hostile
    assert "Remove-Item C:\\ -Recurse #'" not in script.split("ConvertFrom-Json")[0]


def test_netsh_runs_a_powershell_line_from_extras(stub, lan):
    server, ran = stub("windhcp://dhcp01/?method=netsh")
    server.add(lan(extras={"add": ["Write-Output 'extra'"]}))
    assert "Write-Output 'extra'" in ran[0]


def test_netsh_asks_the_server_to_confirm_what_it_applied(stub, lan):
    # netsh exits 0 and says "Command completed successfully" having dropped a
    # value it disliked (measured: option 6 with an unreachable name server), so
    # the payload carries what to verify and where to read it back from.
    server, ran = stub("windhcp://dhcp01/?method=netsh&server=dhcp02")
    server.add(lan(options={"dns": ["10.0.0.53", "10.0.0.54"]}))
    payload = _payload(ran[0])
    assert payload["IPAddress"] == "10.0.0.10"
    assert payload["VerifyArgs"][-1] == "dump"
    assert payload["VerifyArgs"][:3] == ["dhcp", "server", "\\\\dhcp02"]
    counts = {v["Id"]: v["Count"] for v in payload["Verify"]}
    assert counts["6"] == 2  # two name servers must survive, not one
    assert counts["3"] == 1


def test_the_removal_script_has_nothing_to_verify(stub, lan):
    server, ran = stub("windhcp://dhcp01/?method=netsh")
    server.remove(lan())
    assert "Verify" not in _payload(ran[0])


# -- extras ----------------------------------------------------------------


def test_windhcp_cmdlets_take_an_extra_powershell_line(stub, lan):
    server, ran = stub("windhcp://dhcp01/")
    server.add(lan(server, extras={"add": ["Add-DhcpServerv4Policy -Name ipxe"]}))
    assert "Add-DhcpServerv4Policy -Name ipxe" in ran[0]


def test_windhcp_removal_gets_its_own_phase(stub, lan):
    server, ran = stub("windhcp://dhcp01/")
    r = lan(server, extras={"remove": ["Remove-DhcpServerv4Policy -Name ipxe"]})
    server.add(r)
    server.remove(r)
    assert "Remove-DhcpServerv4Policy" not in ran[0]
    assert "Remove-DhcpServerv4Policy -Name ipxe" in ran[1]


def test_windhcp_keep_runs_the_remove_phase_extras(stub, lan):
    server, ran = stub("windhcp://dhcp01/")
    server.complete(
        lan(
            server,
            completion={"keep": True},
            extras={"add": ["Write-Output armed"], "remove": ["Write-Output kept"]},
        )
    )
    assert "Write-Output armed" not in ran[0]
    assert "Write-Output kept" in ran[0]


def test_windhcp_netsh_takes_an_extra_netsh_command(stub, lan):
    server, ran = stub("windhcp://dhcp01/?method=netsh")
    server.add(
        lan(
            extras={
                "add": [
                    {
                        "Args": ["dhcp", "server", "add", "policy", "ipxe"],
                        "Ignore": False,
                    }
                ]
            }
        )
    )
    commands = _commands(ran[0])
    # Last, so the reservation it refers to already exists.
    assert commands[-1] == ["dhcp", "server", "add", "policy", "ipxe"]


def test_netsh_removal_takes_its_phase_extras(stub, lan):
    server, ran = stub("windhcp://dhcp01/?method=netsh")
    server.remove(
        lan(extras={"remove": [{"Args": ["dhcp", "server", "x"], "Ignore": True}]})
    )
    assert _payload(ran[0])["Commands"][-1] == {
        "Args": ["dhcp", "server", "x"],
        "Ignore": True,
    }


def test_a_netsh_command_still_runs_under_the_cmdlet_method(stub, lan):
    # An extra that knows netsh must not be silently dropped when the method is
    # powershell: it becomes the netsh call it describes.
    server, ran = stub("windhcp://dhcp01/")
    server.add(
        lan(
            extras={
                "add": [
                    {
                        "Args": ["dhcp", "server", "add", "policy", "it's"],
                        "Ignore": False,
                    }
                ]
            }
        )
    )
    assert "& netsh 'dhcp' 'server' 'add' 'policy' 'it''s'" in ran[0]
    assert "$LASTEXITCODE" in ran[0]


def test_an_ignored_netsh_command_does_not_abort_the_cmdlet_script(stub, lan):
    server, ran = stub("windhcp://dhcp01/")
    server.add(
        lan(
            extras={
                "add": [
                    {
                        "Args": ["dhcp", "server", "delete", "policy", "ipxe"],
                        "Ignore": True,
                    }
                ]
            }
        )
    )
    assert "Out-Null" in ran[0] and "throw" not in ran[0].split("delete")[-1]


# -- transport=local --------------------------------------------------------


@pytest.fixture
def on_windows(monkeypatch):
    """Make `transport=local` acceptable wherever the suite runs.

    `local` needs Windows PowerShell and is refused elsewhere, but choosing the
    transport, building the argv and handling the exit code are all
    platform-independent -- and testing them on Linux and macOS too is what keeps
    this from being a Windows-only feature with Windows-only coverage.
    """
    import dhcpctl.backends._windhcp as mod

    monkeypatch.setattr(mod._os, "name", "nt")
    return mod


def test_an_empty_host_means_the_shell_is_here(on_windows):
    # `windhcp:///?server=dhcp01` is the ordinary RSAT shape: run PowerShell
    # here, act on that server. There is no host to reach, so none is dialled.
    server = dhcpctl.connect("windhcp:///?server=dhcp01")
    assert server.transport == "local"
    assert server.server == "dhcp01"
    assert server.port is None


def test_a_named_host_still_uses_a_transport():
    # Guessing that `windhcp://dhcp01/` is local because dhcp01 happens to be
    # this machine would surprise whoever wrote the name.
    assert dhcpctl.connect("windhcp://dhcp01/").transport == "ssh"


def test_local_runs_the_same_script_the_other_transports_send(hosts, on_windows, lan):
    import hostctl

    r = lan()
    dhcpctl.connect("windhcp:///?server=dhcp01").add(r)
    dhcpctl.connect("windhcp://host/?server=dhcp01").add(r)
    (local, here), (ssh, there) = hosts
    assert isinstance(local, hostctl.LocalConfig)
    assert isinstance(ssh, hostctl.SSHConfig)
    assert here == there


def test_local_is_refused_where_there_is_no_powershell(monkeypatch):
    # The counterpart: on a POSIX host the default must *not* silently become a
    # transport that cannot work.
    import dhcpctl.backends._windhcp as mod

    monkeypatch.setattr(mod._os, "name", "posix")
    with pytest.raises(dhcpctl.ConfigError, match="needs Windows PowerShell"):
        dhcpctl.connect("windhcp:///?server=dhcp01")
    # ... and an explicit one is refused just as clearly.
    with pytest.raises(dhcpctl.ConfigError, match="needs Windows PowerShell"):
        dhcpctl.connect("windhcp://host/?transport=local")


@pytest.mark.parametrize(
    "option, kind",
    [
        ("router", "IPADDRESS"),
        ("tftp-server-address", "IPADDRESS"),
        ("ip-address-lease-time", "DWORD"),
        ("interface-mtu", "WORD"),
        ("ip-ttl", "BYTE"),
        ("bootfile-name", "STRING"),
        ("option-224", "STRING"),
    ],
)
def test_netsh_is_told_each_option_type_from_its_pydhcp_codec(option, kind):
    from dhcpctl.backends._windhcp import _netsh_type

    assert _netsh_type(dhcpctl.PYDHCP_CODES.resolve(option)) == kind


def test_domain_search_and_next_server_stay_off_a_windows_reservation(stub, lan):
    from dhcpctl.backends._windhcp import _option_ids

    options = dhcpctl.PYDHCP_CODES.options(
        {"domain-search": "example.com", "router": "10.0.0.1"}
    )
    assert _option_ids(options) == [(3, ["10.0.0.1"])]
    # Windows has no per-reservation next-server, so the field is not sent.
    for uri in ("windhcp://dhcp01/", "windhcp://dhcp01/?method=netsh"):
        server, ran = stub(uri)
        server.add(lan(next_server="10.0.0.9"))
        assert "10.0.0.9" not in ran[-1]


def test_a_reservation_without_an_address_is_refused_before_any_script(stub, lan):
    server, ran = stub()
    with pytest.raises(dhcpctl.ConfigError, match="no ip address"):
        server.add(lan(ip=None))
    assert ran == []


def test_a_netsh_command_given_as_one_string_is_refused(stub, lan):
    # One string would reach netsh as one argument per character.
    server, ran = stub("windhcp://dhcp01/?method=netsh")
    with pytest.raises(dhcpctl.ConfigError, match="list of arguments"):
        server.add(lan(extras={"add": [{"Args": "dhcp server add policy ipxe"}]}))
    assert ran == []


@pytest.mark.parametrize("stdout", ["", "{}", "item 1\n"])
def test_a_script_that_does_not_reach_its_end_is_a_server_error(hosts, lan, stdout):
    server = dhcpctl.connect("windhcp://dhcp01/")
    hosts.result = _Completed(stdout=stdout)
    with pytest.raises(dhcpctl.ServerError, match="without finishing"):
        server.add(lan())


def _sent_netsh(uri, reservation, action="add"):
    server = dhcpctl.connect(uri)
    sent = []
    server.run = lambda payload, body: sent.append((payload, body))
    getattr(server, action)(reservation)
    return sent


def test_netsh_verifies_what_it_sent_not_what_a_policy_serves(reservation):
    r = reservation(
        options={"router": "10.0.0.1", "file": "undionly.kpxe"},
        conditions={
            "ipxe": {"match": {"user-class": "iPXE"}, "options": {"file": "b"}}
        },
    )
    sent = _sent_netsh("windhcp://dhcp01/?method=netsh", r)
    payload = next(p for p, _ in sent if "Verify" in p)
    set_ids = [
        c["Args"][-3] for c in payload["Commands"] if "reservedoptionvalue" in c["Args"]
    ]
    assert [v["Id"] for v in payload["Verify"]] == set_ids
    assert "67" not in set_ids, "option 67 is the policy's"


def test_netsh_keep_uses_netsh(reservation):
    r = reservation(
        options={"router": "10.0.0.1", "file": "undionly.kpxe", "tftp-server": "t"},
        completion={"keep": True, "options": {"file": "sanboot.ipxe"}},
    )
    sent = _sent_netsh("windhcp://dhcp01/?method=netsh", r, "keep")
    ((payload, body),) = sent
    script = "\n".join(body)
    assert "Set-DhcpServerv4OptionValue" not in script
    assert "Remove-DhcpServerv4OptionValue" not in script
    commands = [c["Args"][4:] for c in payload["Commands"]]
    assert [
        "set",
        "reservedoptionvalue",
        "10.0.0.10",
        "67",
        "STRING",
        "sanboot.ipxe",
    ] in commands
    assert ["delete", "reservedoptionvalue", "10.0.0.10", "66"] in commands
    assert [v["Id"] for v in payload["Verify"]] == ["3", "67"]


def test_what_a_windows_reservation_cannot_carry_is_warned_about(reservation, caplog):
    r = reservation(options={"domain-search": ["example.com"]}, next_server="10.0.0.2")
    with caplog.at_level("WARNING", logger="dhcpctl"):
        _sent_netsh("windhcp://dhcp01/", r)
    assert "option 119" in caplog.text and "next-server 10.0.0.2" in caplog.text


def test_a_flag_is_the_byte_windows_stores():
    from dhcpctl.backends._windhcp import _values

    assert _values(True) == [1] and _values(False) == [0]
    assert _values(["10.0.0.1", "10.0.0.2"]) == ["10.0.0.1", "10.0.0.2"]
