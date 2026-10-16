"""The DHCP option model: what the query string carries, and what it refuses.

Two vocabularies share a backend's query string -- its own connection settings
and the client options -- so the tests here are mostly about keeping them apart,
and about refusing anything that varies per client (a boot file pinned to a
connection would hand every client on that server the same one).
"""

import pytest

import dhcpctl
from dhcpctl import backends
from dhcpctl._options import split_query
from dhcpctl import APPLY_TIME, GENERIC_OPTIONS, DHCPOptions, is_option

#: A backend's settings, for splitting tests.
SETTINGS = frozenset({"hostsfile", "reload"})


def test_settings_and_options_split_by_vocabulary():
    settings, options, builder = split_query(
        "fake://h?hostsfile=/etc/x&reload=systemctl+reload+d&router=10.0.0.1",
        SETTINGS,
        "fake",
    )
    assert settings == {"hostsfile": "/etc/x", "reload": "systemctl reload d"}
    assert options == {"router": "10.0.0.1"}
    assert builder is None


def test_a_repeated_key_is_a_list():
    _, options, _ = split_query(
        "fake://h?domain-name-servers=10.0.0.53&domain-name-servers=10.0.0.54",
        SETTINGS,
        "fake",
    )
    assert options["domain-name-servers"] == ["10.0.0.53", "10.0.0.54"]


def test_raw_is_kept_per_backend_and_never_translated():
    _, options, _ = split_query(
        "fake://h?raw.dnsmasq=dhcp-option%3Dtag%3Ax%2C66%2C10.0.0.2",
        SETTINGS,
        "fake",
    )
    assert options.raw_for("dnsmasq") == ["dhcp-option=tag:x,66,10.0.0.2"]
    assert options.raw_for("kea") == []
    assert dict(options) == {}


def test_a_raw_key_with_a_phase_is_kept_under_that_phase():
    _, options, _ = split_query(
        "fake://h?raw.dhcpd=a;&raw.dhcpd.add=b;&raw.dhcpd.remove=c;",
        SETTINGS,
        "fake",
    )
    assert options.raw == {"dhcpd": ["a;"], "dhcpd.add": ["b;"], "dhcpd.remove": ["c;"]}
    # The unsuffixed one first: it was written as "the" fragment.
    assert options.raw_for("dhcpd") == ["a;", "b;"]
    assert options.raw_for("dhcpd", "remove") == ["c;"]


def test_the_options_builder_is_split_out_and_not_an_option():
    _, options, builder = split_query(
        "fake://h?options_builder=site.dhcp:build&router=10.0.0.1", SETTINGS, "fake"
    )
    assert builder == "site.dhcp:build"
    assert options == {"router": "10.0.0.1"}


def test_an_unknown_key_names_both_vocabularies():
    with pytest.raises(dhcpctl.ConfigError) as excinfo:
        split_query("fake://h?nosuchthing=1", SETTINGS, "fake")
    message = str(excinfo.value)
    assert "nosuchthing" in message and "hostsfile" in message and "router" in message


@pytest.mark.parametrize("key", sorted(APPLY_TIME))
def test_an_apply_time_key_is_refused_and_says_where_it_belongs(key):
    with pytest.raises(dhcpctl.ConfigError) as excinfo:
        split_query(f"fake://h?{key}=x", SETTINGS, "fake")
    message = str(excinfo.value)
    assert key in message
    assert APPLY_TIME[key] in message


def test_numeric_options_are_always_accepted():
    assert is_option("option-66") and is_option("66")
    assert not is_option("option-abc")
    assert not is_option("option-")
    _, options, _ = split_query("fake://h?option-66=10.0.0.2", SETTINGS, "fake")
    assert options["option-66"] == "10.0.0.2"


@pytest.mark.parametrize("name", sorted(GENERIC_OPTIONS))
def test_every_generic_option_is_an_option(name):
    assert is_option(name)


def test_an_unmodelled_name_is_not_an_option():
    assert not is_option("server-identifier")
    assert not is_option("")


def test_shipped_backend_settings_never_collide_with_option_names():
    # A backend that names a setting `server-identifier` would silently eat that
    # option; this is the test that stops it, before an operator's boot does.
    for name in backends.__all__:
        backend = getattr(backends, name)
        overlap = set(backend.SETTINGS) & (GENERIC_OPTIONS | set(APPLY_TIME))
        assert not overlap, f"{name} settings collide with options: {overlap}"


def test_dhcp_options_copy_keeps_raw():
    options = DHCPOptions({"router": "10.0.0.1"}, raw={"dnsmasq": ["x"]})
    clone = options.copy()
    clone["router"] = "10.0.0.2"
    assert options["router"] == "10.0.0.1"
    assert clone.raw_for("dnsmasq") == ["x"]
    assert isinstance(clone, DHCPOptions)


def test_a_copy_does_not_share_the_raw_lists():
    options = DHCPOptions(raw={"dnsmasq": ["x"]})
    clone = options.copy()
    clone.raw["dnsmasq"].append("y")
    assert options.raw_for("dnsmasq") == ["x"]
