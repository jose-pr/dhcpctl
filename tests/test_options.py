"""The DHCP option model: the codemaps options are named by, and the values they hold.

Options are pydhcp's, keyed by code; the names an option goes by are a
codemap (`option_codes`): pydhcp's, under whatever a backend or a caller
declares. `next-server` and `file` are no options but BOOTP header fields a
lease carries beside them.
A server URI carries no options at all (`test_registry.py`).
"""

import ipaddress

import pytest

from pydhcp.options import Bytes, String

import dhcpctl
from dhcpctl import (
    BOOT_FIELDS,
    PYDHCP_CODES,
    UNSPECIFIED,
    DHCPOptionCode,
    DHCPOptions,
    OptionCodes,
    option_codes,
    plain_items,
)

#: Every name pydhcp's registry gives, as dhcpctl spells it.
PYDHCP_SPELLINGS = sorted(
    name.lower().replace("_", "-")
    for name, member in DHCPOptionCode.__members__.items()
    if member not in (DHCPOptionCode.PAD, DHCPOptionCode.END)
)


@pytest.mark.parametrize("name", PYDHCP_SPELLINGS)
def test_every_pydhcp_option_name_is_an_option(name):
    assert PYDHCP_CODES.knows(name)
    assert int(PYDHCP_CODES.resolve(name)) == int(
        DHCPOptionCode[name.upper().replace("-", "_")]
    )


@pytest.mark.parametrize(
    "spelling",
    [
        "bootfile-name",
        "BOOTFILE_NAME",
        "Bootfile_Name",
        "option-67",
        "67",
        67,
    ],
)
def test_every_spelling_of_one_option_is_one_key(spelling):
    assert PYDHCP_CODES.resolve(spelling) is PYDHCP_CODES.BOOTFILE_NAME
    assert PYDHCP_CODES.resolve(spelling) == DHCPOptionCode.BOOTFILE_NAME


def test_a_codemap_member_is_its_name_as_text_and_its_code_as_a_number():
    router = PYDHCP_CODES.resolve("router")
    assert isinstance(router, OptionCodes)
    assert str(router) == router.label() == "ROUTER"
    assert int(router) == 3
    # A declared alias is the canonical member, not a name of its own.
    gw = option_codes({"gw": "router"}).resolve("gw")
    assert str(gw) == gw.label() == "ROUTER"
    assert int(gw) == 3
    # A declared option is named as declared.
    assert str(option_codes({"my-option": 224}).resolve("my-option")) == "MY_OPTION"


def test_a_code_with_no_name_is_an_unknown_member():
    unnamed = PYDHCP_CODES.resolve(224)
    assert isinstance(unnamed, PYDHCP_CODES)
    assert unnamed.label() == str(unnamed) == "UNKNOWN"
    assert int(unnamed) == 224
    assert unnamed.get_type() is Bytes
    assert PYDHCP_CODES.resolve("option-224") is unnamed, "one member per code"


@pytest.mark.parametrize(
    "uri, alias, code",
    [
        ("kea://h/", "routers", 3),
        ("kea://h/", "domain-name-servers", 6),
        ("kea://h/", "dhcp-lease-time", 51),
        ("kea://h/", "tftp-server-name", 66),
        ("kea://h/", "host-name", 12),
        ("dhcpd://h/", "routers", 3),
        ("dhcpd://h/", "domain-name-servers", 6),
        ("dhcpd://h/", "dhcp-lease-time", 51),
        ("dhcpd://h/", "tftp-server-name", 66),
        ("dhcpd://h/", "host-name", 12),
    ],
)
def test_each_backend_reads_its_own_spellings(uri, alias, code):
    server = dhcpctl.connect(uri)
    assert int(server.codes.resolve(alias)) == code
    assert option_codes(type(server).OPTION_NAMES).knows(alias)
    # A backend's spelling is that backend's, not everyone's.
    assert not PYDHCP_CODES.knows(alias)


@pytest.mark.parametrize(
    "uri, alias, field",
    [
        ("kea://h/", "boot-file-name", "file"),
        ("kea://h/", "server-hostname", "sname"),
        ("dhcpd://h/", "filename", "file"),
        ("dhcpd://h/", "server-name", "sname"),
    ],
)
def test_each_backend_names_the_header_fields_its_own_way(uri, alias, field):
    server = dhcpctl.connect(uri)
    assert server.codes.field(alias) == field
    assert getattr(server.codes.lease({alias: "x"}), field) == "x"
    assert PYDHCP_CODES.field(alias) is None


def test_a_caller_declares_a_header_field_alias():
    codes = option_codes({"boot-file-name": "file", "tftp": "next-server"})
    lease = codes.lease({"boot-file-name": "a.efi", "tftp": "10.0.0.2"})
    assert lease.file == "a.efi" and str(lease.siaddr) == "10.0.0.2"
    # Declared again as an option, over it, the name is an option again.
    again = option_codes({"boot-file-name": "bootfile-name"}, base=codes)
    assert again.field("boot-file-name") is None
    assert again.lease({"boot-file-name": "b"}).options.get(67) == "b"


def test_a_caller_declares_its_own_alias():
    codes = option_codes({"Lease_Time": 51})
    assert int(codes.resolve("lease-time")) == 51
    assert int(codes.resolve("LEASE_TIME")) == 51
    assert dict(plain_items(codes.options({"lease-time": 600}))) == {51: 600}
    # Declared names live in that codemap only: nothing process-wide changes.
    assert not PYDHCP_CODES.knows("lease-time")


def test_a_declared_option_has_a_code_and_a_type():
    codes = option_codes({"my-option": {"code": 224, "type": "String"}})
    assert codes.resolve("MY_OPTION") == 224
    options = codes.options({"my-option": "anything"})
    assert dict(plain_items(options)) == {224: "anything"}
    assert options.get(224) == "anything"
    # A bag built with that codemap decodes 224 as text, off the wire too...
    wire = DHCPOptions.decode(bytes([224, 2]) + b"hi" + bytes([255]), codemap=codes)
    assert wire.get(224) == "hi"
    # ...and the type is that codemap's: pydhcp's registry is not changed.
    assert DHCPOptionCode(224).get_type() is Bytes
    assert PYDHCP_CODES.resolve(224).get_type() is Bytes
    with pytest.raises(dhcpctl.ConfigError, match="option 224 cannot hold a str"):
        PYDHCP_CODES.options({"option-224": "x"})


def test_a_declared_type_may_be_a_list_of_a_codec():
    codes = option_codes({"proxies": {"code": 224, "type": "List[IPv4AddressOption]"}})
    options = codes.options({"proxies": ["10.0.0.1", "10.0.0.2"]})
    assert dict(plain_items(options)) == {224: ["10.0.0.1", "10.0.0.2"]}
    assert DHCPOptionCode(224).get_type() is Bytes


def test_a_declared_type_may_retype_an_option_pydhcp_types():
    codes = option_codes({"dns-text": {"code": 6, "type": "String"}})
    assert codes.resolve("dns").get_type() is String
    assert dict(plain_items(codes.options({"dns": "ns.example"}))) == {6: "ns.example"}
    # pydhcp's own codemap still reads option 6 as a list of addresses.
    assert dict(plain_items(PYDHCP_CODES.options({"dns": "10.0.0.53"}))) == {
        6: ["10.0.0.53"]
    }
    assert DHCPOptionCode.DNS.get_type() is not String


def test_a_declared_option_without_a_type_keeps_pydhcps():
    codes = option_codes({"my-option": {"code": 224}})
    assert codes.resolve("my-option") == 224
    assert dict(plain_items(codes.options({"my-option": b"\x01"}))) == {224: "01"}


def test_an_alias_names_another_option_by_name():
    codes = option_codes({"domain-name-servers": "dns"})
    assert codes.resolve("domain-name-servers") is codes.DNS
    assert codes.resolve("domain-name-servers") == DHCPOptionCode.DNS
    options = codes.options({"domain-name-servers": "10.0.0.53"})
    assert dict(plain_items(options)) == {6: ["10.0.0.53"]}


def test_an_alias_names_another_option_by_code():
    codes = option_codes({"gateway": 3})
    assert codes.resolve("gateway") is codes.ROUTER
    assert dict(plain_items(codes.options({"gateway": "10.0.0.1"}))) == {
        3: ["10.0.0.1"]
    }


def test_an_alias_may_name_another_declared_name():
    codes = option_codes({"my-option": {"code": 224}, "mine": "my-option"})
    assert codes.resolve("mine") == 224


def test_declared_codes_stack_over_a_base():
    base = option_codes({"routers": "router", "lease": 51})
    codes = option_codes({"gw": "routers", "lease": 58}, base=base)
    # An alias reaches the base's names, and the base pydhcp's.
    assert codes.resolve("gw") == DHCPOptionCode.ROUTER
    assert codes.resolve("routers") == DHCPOptionCode.ROUTER
    assert codes.resolve("dns") == DHCPOptionCode.DNS
    # The upper layer wins, and the base is not changed by having one.
    assert codes.resolve("lease") == 58
    assert base.resolve("lease") == 51
    assert not base.knows("gw")


def test_over_stacks_every_layer_over_another_base():
    lower = option_codes({"x": 224})
    upper = option_codes({"y": "x"}, base=lower)
    other = option_codes({"z": 3, "x": 225})
    stacked = upper.over(other)
    assert stacked.resolve("y") == 224, "every layer of `upper` comes along"
    assert stacked.resolve("x") == 224, "and wins over the new base"
    assert stacked.resolve("z") == 3
    # Neither side is changed.
    assert not upper.knows("z") and not other.knows("y")
    assert other.resolve("x") == 225


def test_option_codes_of_takes_a_codemap_a_mapping_or_nothing():
    codes = option_codes({"gw": 3})
    assert OptionCodes.of(codes) is codes
    assert OptionCodes.of(None) is PYDHCP_CODES
    assert OptionCodes.of({}) is PYDHCP_CODES
    assert OptionCodes.of({"gw": 3}).resolve("gw") == 3


def test_pydhcp_codes_declares_nothing():
    assert PYDHCP_CODES.resolve("router") == DHCPOptionCode.ROUTER
    assert not PYDHCP_CODES.knows("routers")
    assert not PYDHCP_CODES.knows("boot-file-name")


def test_a_pydhcp_name_cannot_be_given_another_code():
    with pytest.raises(dhcpctl.ConfigError, match="pydhcp's name for option 3"):
        option_codes({"router": 6})
    with pytest.raises(dhcpctl.ConfigError, match="pydhcp's name for option 3"):
        option_codes({"ROUTER": {"code": 6}})
    # Its own code again changes nothing.
    assert option_codes({"router": 3}).resolve("router") == DHCPOptionCode.ROUTER


@pytest.mark.parametrize(
    "declared, message",
    [
        ({"x": {"code": 224, "kind": "String"}}, "takes `code`.*not kind"),
        ({"x": {"type": "String"}}, "takes `code`"),
        ({"x": {"code": 300}}, r"options\.x\.code.*not a valid DHCPOptionCode"),
        ({"x": {"code": -1}}, r"options\.x\.code.*not a valid DHCPOptionCode"),
        ({"x": {"code": "abc"}}, r"options\.x\.code"),
        ({"x": {"code": 224, "type": "NoSuchCodec"}}, "unknown option type"),
        ({"x": {"code": 224, "type": "List[NoSuchCodec]"}}, "unknown option type"),
        ({"x": 1.5}, "must be a code, a name or"),
        ({"x": True}, "must be a code, a name or"),
        ({"dns": 3}, "pydhcp's name for option 6"),
    ],
)
def test_a_declaration_that_cannot_be_used_is_refused(declared, message):
    with pytest.raises(dhcpctl.ConfigError, match=message):
        option_codes(declared)


@pytest.mark.parametrize(
    "declared",
    [{"a": "b", "b": "a"}, {"a": "a"}, {"a": "b", "b": "c", "c": "a"}],
)
def test_an_alias_loop_is_refused(declared):
    with pytest.raises(dhcpctl.ConfigError, match=r"^options\.a: .*loop"):
        option_codes(declared)


@pytest.mark.parametrize("name", sorted(BOOT_FIELDS))
def test_a_header_field_is_no_option(name):
    # siaddr, sname and file are BOOTP header fields, carried beside the options.
    assert PYDHCP_CODES.field(name) == BOOT_FIELDS[name]
    assert PYDHCP_CODES.knows(name)
    with pytest.raises(ValueError):
        PYDHCP_CODES.resolve(name)
    with pytest.raises(dhcpctl.ConfigError, match="unknown option"):
        PYDHCP_CODES.options({name: "x"})


def test_header_fields_are_taken_out_of_a_config_mapping():
    lease = PYDHCP_CODES.lease(
        {"Next_Server": "10.0.0.2", "router": "10.0.0.1", "file": "a.efi"}
    )
    assert lease.siaddr == ipaddress.IPv4Address("10.0.0.2")
    assert lease.file == "a.efi" and lease.sname == ""
    assert dict(plain_items(lease.options)) == {3: ["10.0.0.1"]}
    assert lease.ip == UNSPECIFIED


def test_option_67_is_not_the_file_field():
    lease = PYDHCP_CODES.lease({"bootfile-name": "a.efi"})
    assert lease.file == "" and lease.options.get(67) == "a.efi"


@pytest.mark.parametrize("value", ["tftp.example", "10.0.0.256", "::1"])
def test_a_next_server_that_is_no_ipv4_address_is_refused(value):
    with pytest.raises(dhcpctl.ConfigError):
        PYDHCP_CODES.lease({"next-server": value})


@pytest.mark.parametrize("value", [None, ""])
def test_an_empty_header_field_is_unset(value):
    lease = PYDHCP_CODES.lease({"next-server": value, "file": value})
    assert lease.siaddr == UNSPECIFIED and lease.file == ""


def test_unspecified_is_the_all_zero_address():
    assert UNSPECIFIED == ipaddress.IPv4Address("0.0.0.0")
    assert UNSPECIFIED.is_unspecified


def test_condition_and_completion_check_their_next_server():
    with pytest.raises(dhcpctl.ConfigError):
        dhcpctl.Condition("c", {"user-class": "iPXE"}, {"next-server": "nope"})
    with pytest.raises(dhcpctl.ConfigError):
        dhcpctl.Completion(keep=True, lease={"next-server": "nope"})
    with pytest.raises(dhcpctl.ConfigError, match="dhcp_complete.options"):
        dhcpctl.parse_completion(
            {"keep": True, "options": {"next-server": "nope"}}, "test"
        )


def test_a_lease_is_returned_as_it_is():
    lease = PYDHCP_CODES.lease({"file": "a"})
    assert PYDHCP_CODES.lease(lease) is lease


def test_a_code_pydhcp_has_no_name_for_is_named_by_number():
    assert int(PYDHCP_CODES.resolve("option-224")) == 224
    assert int(PYDHCP_CODES.resolve(224)) == 224


@pytest.mark.parametrize(
    "name", ["", "nosuch", "option-abc", "option-", "option-300", "-1", True]
)
def test_what_is_not_an_option(name):
    assert not PYDHCP_CODES.knows(name)
    with pytest.raises((TypeError, ValueError)):
        PYDHCP_CODES.resolve(name)


def test_an_unknown_name_is_refused_by_name():
    with pytest.raises(dhcpctl.ConfigError, match="unknown option 'nosuch'"):
        PYDHCP_CODES.options({"nosuch": 1})


@pytest.mark.parametrize("name", ["option-300", 300])
def test_a_code_out_of_range_is_refused(name):
    with pytest.raises(ValueError, match=r"300"):
        PYDHCP_CODES.resolve(name)


def test_options_are_one_key_however_they_are_written():
    options = PYDHCP_CODES.options({"bootfile-name": "a.efi"})
    options.update(PYDHCP_CODES.options({"BOOTFILE_NAME": "b.efi"}))
    assert list(options) == [DHCPOptionCode.BOOTFILE_NAME]
    assert options.get(67) == "b.efi"
    assert options[67] == bytearray(b"b.efi"), "[] is the raw payload"
    assert 67 in options and 66 not in options
    assert {int(k): v for k, v in plain_items(options)} == {67: "b.efi"}


def test_a_bag_is_built_with_the_codemap_that_read_it():
    codes = option_codes({"gw": "router"})
    options = codes.options({"gw": "10.0.0.1"})
    assert [type(code) for code, _ in plain_items(options)] == [codes]
    # A copy keeps it.
    assert [type(code) for code, _ in plain_items(options.copy())] == [codes]


def test_update_takes_the_codemaps_names_aliases_included():
    codes = option_codes({"gw": "router"})
    options = codes.options({"router": "10.0.0.1"})
    options.update(GW="10.0.0.9")
    assert dict(plain_items(options)) == {3: ["10.0.0.9"]}
    options.update(gw="10.0.0.8", ROUTER="10.0.0.7")
    assert dict(plain_items(options)) == {3: ["10.0.0.7"]}
    # An alias is that codemap's alone.
    with pytest.raises(TypeError, match="unknown option 'GW'"):
        PYDHCP_CODES.options({}).update(GW="10.0.0.9")


def test_the_container_is_keyed_by_code_only():
    # Names are read by a codemap; the container itself takes ints.
    options = DHCPOptions()
    with pytest.raises(TypeError, match="option code must be an int"):
        options["router"] = "10.0.0.1"
    options[PYDHCP_CODES.resolve("router")] = "10.0.0.1"
    assert dict(plain_items(options)) == {3: ["10.0.0.1"]}


def test_a_value_the_option_cannot_hold_is_refused():
    with pytest.raises(
        dhcpctl.ConfigError, match=r"option 3 \(ROUTER\) cannot hold a str: .*not-an-ip"
    ):
        PYDHCP_CODES.options({"router": "not-an-ip"})
    with pytest.raises(
        dhcpctl.ConfigError, match=r"option 51 \(IP_ADDRESS_LEASE_TIME\) cannot hold"
    ):
        PYDHCP_CODES.options({"ip-address-lease-time": "forever"})
    with pytest.raises(dhcpctl.ConfigError, match=r"\(on 'web01'\)$"):
        PYDHCP_CODES.options({"router": "not-an-ip"}, where="web01")


def test_a_value_is_stored_as_the_codec_reads_it():
    options = PYDHCP_CODES.options(
        {"router": "10.0.0.1", "ip-address-lease-time": "3600", "domain-name": "a,b"}
    )
    assert dict(plain_items(options)) == {
        3: ["10.0.0.1"],  # router is a list of addresses
        51: 3600,
        15: "a,b",
    }
    assert options.get(51) == 3600


def test_a_comma_joined_list_is_not_a_list():
    # pydhcp reads one address per item; repeat the key for several.
    with pytest.raises(dhcpctl.ConfigError, match=r"option 6 \(DNS\)"):
        PYDHCP_CODES.options({"dns": "10.0.0.53,10.0.0.54"})


@pytest.mark.parametrize("value", [b"\x01\x02", "0102", "01:02", {"hex": "0102"}])
def test_an_opaque_option_takes_bytes_or_hex(value):
    options = PYDHCP_CODES.options({"option-224": value})
    assert dict(plain_items(options)) == {224: "0102"}


def test_an_opaque_option_refuses_text_that_is_not_hex():
    with pytest.raises(dhcpctl.ConfigError, match="option 224 cannot hold a str"):
        PYDHCP_CODES.options({"option-224": "anything"})


def test_an_enum_option_takes_its_member_name():
    options = PYDHCP_CODES.options({"dhcp-message-type": "DHCPACK"})
    assert options.to_mapping() == {"DHCP_MESSAGE_TYPE": "DHCPACK"}


def test_a_codemap_takes_the_codecs_pydhcp_has_when_it_is_made():
    DHCPOptionCode(224).register_type(String)
    try:
        options = option_codes().options({"option-224": "anything"})
        assert dict(plain_items(options)) == {224: "anything"}
    finally:
        DHCPOptionCode(224).register_type(Bytes)


def test_a_codec_registered_on_a_codemap_stays_in_it():
    codes = option_codes()
    codes(224).register_type(String)
    assert dict(plain_items(codes.options({"option-224": "x"}))) == {224: "x"}
    assert DHCPOptionCode(224).get_type() is Bytes
    assert PYDHCP_CODES(224).get_type() is Bytes


def test_reading_a_dhcp_options_copies_it():
    options = PYDHCP_CODES.options({"router": "10.0.0.1"})
    clone = PYDHCP_CODES.options(options)
    assert clone == options and clone is not options
    clone[3] = "10.0.0.2"
    assert dict(plain_items(options)) == {3: ["10.0.0.1"]}
    assert isinstance(clone, DHCPOptions)


@pytest.mark.parametrize(
    "declared, message",
    [
        ({"dns": "router"}, "pydhcp's name for option 6"),
        ({"option-12": 3}, "cannot be declared"),
        ({"12": 3}, "cannot be declared"),
        ({"next-server": 3}, "cannot be declared"),
        ({"x": "nosuch"}, "no option .* to alias"),
        ({"a": "b", "b": "a"}, "loop"),
        ({"x": {"code": True}}, "code must be"),
    ],
)
def test_a_declaration_is_refused_when_it_is_made(declared, message):
    with pytest.raises(dhcpctl.ConfigError, match=message) as refused:
        option_codes(declared)
    assert str(refused.value).startswith(f"options.{next(iter(declared))}")


def test_a_refused_declaration_registers_no_type():
    before = dhcpctl.DHCPOptionCode(224).get_type()
    with pytest.raises(dhcpctl.ConfigError):
        option_codes({"mine": {"code": 224, "type": "String"}, "dns": "router"})
    assert dhcpctl.DHCPOptionCode(224).get_type() is before is Bytes


@pytest.mark.parametrize("name", ["0", "option-255", 0, 255])
def test_pad_and_end_are_codes_pydhcp_will_not_store(name):
    # They name pydhcp's framing markers; pydhcp refuses them as options.
    with pytest.raises(dhcpctl.ConfigError, match="not an option"):
        PYDHCP_CODES.options({name: b"x"})


def test_two_spellings_of_one_name_are_refused():
    with pytest.raises(dhcpctl.ConfigError, match="'A' and 'a' are one name"):
        dhcpctl.option_codes({"a": 3, "A": 4})


def test_a_declaration_error_names_what_was_written():
    with pytest.raises(dhcpctl.ConfigError, match=r"^options\.b: no option 'nosuch'"):
        dhcpctl.option_codes({"a": 3, "b": "nosuch"})
    with pytest.raises(dhcpctl.ConfigError, match="a -> b -> a loop"):
        dhcpctl.option_codes({"a": "b", "b": "a"})


@pytest.mark.parametrize("name", ["option-300", 300])
def test_an_out_of_range_code_reports_pydhcps_message(name):
    with pytest.raises(dhcpctl.ConfigError, match="must be in range 1-254, got 300"):
        PYDHCP_CODES.options({name: b"x"})
