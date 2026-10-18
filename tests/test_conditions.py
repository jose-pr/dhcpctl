"""Named conditions, and what each backend makes of one.

The worked example is the iPXE chainload: serve the iPXE binary to a PXE ROM and
the script to iPXE, or iPXE loads itself forever. The point of the feature is to
say that **once**, under a name, and have each backend use the name for its own
construct -- a Windows policy, a dhcpd group or inline `if`, a Kea client class.
"""

import json

import pytest

import dhcpctl
import ipaddress

from dhcpctl import MATCH_KEYS, UNSPECIFIED, Condition, parse_conditions

IPXE = {
    "ipxe": {
        "match": {"user-class": "iPXE"},
        "options": {"file": "boot.ipxe"},
    }
}

#: What the client is served when no condition matches.
BASE = {"file": "undionly.kpxe", "subnet-mask": "255.255.255.0"}


@pytest.fixture
def armed(reservation):
    """`web01` with the base boot file and the `ipxe` condition."""

    def build(**kwargs):
        kwargs.setdefault("options", BASE)
        kwargs.setdefault("conditions", IPXE)
        kwargs.setdefault("subnet_id", 1)
        return reservation(**kwargs)

    return build


# -- the model --------------------------------------------------------------


def test_a_condition_is_keyed_by_the_name_backends_will_use():
    conditions = parse_conditions(IPXE, "debian")
    assert list(conditions) == ["ipxe"]
    assert conditions["ipxe"].name == "ipxe"
    assert conditions["ipxe"].match == {"user-class": "iPXE"}
    assert conditions["ipxe"].option_codes == {77: "iPXE"}
    assert conditions["ipxe"].lease.file == "boot.ipxe"
    assert len(conditions["ipxe"].lease.options) == 0
    assert conditions["ipxe"].lease.siaddr == UNSPECIFIED


def test_a_next_server_key_in_the_options_is_the_condition_next_server():
    conditions = parse_conditions(
        {
            "ipxe": {
                "match": {"user-class": "iPXE"},
                "options": {"file": "boot.ipxe", "next-server": "10.0.0.2"},
            }
        },
        "debian",
    )
    assert conditions["ipxe"].lease.siaddr == ipaddress.IPv4Address("10.0.0.2")
    assert conditions["ipxe"].lease.file == "boot.ipxe"


def test_a_condition_next_server_is_checked_where_it_is_declared():
    with pytest.raises(dhcpctl.ConfigError, match="dhcp_when.ipxe on 'debian': siaddr"):
        parse_conditions(
            {
                "ipxe": {
                    "match": {"user-class": "iPXE"},
                    "options": {"next-server": "tftp.example"},
                }
            },
            "debian",
        )


def test_conditions_differing_only_in_next_server_are_not_equal():
    a = Condition("ipxe", {"user-class": "iPXE"}, {"file": "x"})
    b = Condition(
        "ipxe", {"user-class": "iPXE"}, {"file": "x", "next-server": "10.0.0.2"}
    )
    assert a != b


def test_nothing_declared_is_no_conditions():
    assert parse_conditions(None, "debian") == {}
    assert parse_conditions({}, "debian") == {}


def test_conditions_compare_by_content():
    a = Condition("ipxe", {"user-class": "iPXE"}, {"file": "x"})
    b = Condition("ipxe", {"user-class": "iPXE"}, {"file": "x"})
    c = Condition("ipxe", {"user-class": "iPXE"}, {"file": "y"})
    assert a == b and a != c


def test_a_declaration_that_is_not_a_mapping_is_refused():
    with pytest.raises(dhcpctl.ConfigError, match="mapping of name"):
        parse_conditions(["ipxe"], "debian")


@pytest.mark.parametrize(
    "entry, message",
    [
        ("not-a-mapping", "must be a mapping"),
        ({"match": {}, "options": {"file": "x"}}, "non-empty `match`"),
        ({"match": {"user-class": "iPXE"}}, "non-empty `options`"),
        (
            {"match": {"hostname": "x"}, "options": {"file": "y"}},
            "cannot match",
        ),
        (
            {"match": {"user-class": "x"}, "options": {"nonsense": "y"}},
            "unknown option",
        ),
        (
            {
                "match": {"user-class": "x"},
                "options": {"file": "y"},
                "zzz": 1,
            },
            "unknown key",
        ),
    ],
)
def test_a_malformed_condition_names_the_mistake(entry, message):
    with pytest.raises(dhcpctl.ConfigError, match=message) as excinfo:
        parse_conditions({"bad": entry}, "debian")
    # ... and the object that declared it, so the mistake can be found.
    assert "'debian'" in str(excinfo.value)


def test_a_name_that_no_backend_could_use_is_refused():
    # The name reaches a PowerShell argument, a dhcpd identifier and a Kea class
    # name; it is kept to the intersection rather than quoted three ways.
    declared = {"bad name": {"match": {"user-class": "x"}, "options": {"file": "y"}}}
    with pytest.raises(dhcpctl.ConfigError, match="letters, digits"):
        parse_conditions(declared, "debian")


def test_the_accepted_match_keys_are_the_ones_every_backend_can_test():
    assert set(MATCH_KEYS) == {"user-class", "vendor-class"}


# -- windhcp: a scope-level policy -----------------------------------------


def _windhcp(uri="windhcp://dhcp01/", **kwargs):
    server = dhcpctl.connect(uri, **kwargs)
    sent = []
    server.run = lambda payload, body: sent.append((payload, body))
    return server, sent


def _payload_of(sent, key):
    return next(payload for payload, _ in sent if key in payload)


def test_windhcp_ensuring_one_condition_bases_only_its_own_options(reservation):
    # The base policy carries what the reservation would have said for the
    # options *this* condition overrides; another condition's are its own.
    server, sent = _windhcp()
    r = reservation(
        options={"file": "undionly.kpxe", "tftp-server": "10.0.0.2"},
        conditions={
            "ipxe": {
                "match": {"user-class": "iPXE"},
                "options": {"file": "boot.ipxe"},
            },
            "uefi": {
                "match": {"vendor-class": "PXEClient:Arch:00007"},
                "options": {"tftp-server": "10.0.0.3"},
            },
        },
    )
    server.ensure_condition(r, r.conditions["ipxe"])
    policies = _payload_of(sent, "Policies")["Policies"]
    assert [p["Name"] for p in policies] == [
        "dhcpctl-aabbccddeeff-ipxe",
        "dhcpctl-aabbccddeeff",
    ]
    assert policies[1]["Options"] == [{"Id": 67, "Value": ["undionly.kpxe"]}]


def test_windhcp_creates_the_policy_before_the_reservation(armed):
    server, sent = _windhcp()
    server.add(armed())
    assert "Policies" in sent[0][0], "the policy script must come first"
    assert "IPAddress" in sent[1][0]
    policy = _payload_of(sent, "Policies")["Policies"][0]
    # Per client by default, and named for the MAC, because a Windows policy is
    # scope-level and the MAC is the only condition that narrows it to one host.
    assert policy["Name"] == "dhcpctl-aabbccddeeff-ipxe"
    assert policy["UserClass"] == "iPXE"
    assert policy["MacAddress"] == "aabbccddeeff"
    assert policy["Options"] == [{"Id": 67, "Value": ["boot.ipxe"]}]


def test_windhcp_policy_names_use_the_owner(armed):
    server, sent = _windhcp(owner="netboot")
    server.add(armed())
    names = [p["Name"] for p in _payload_of(sent, "Policies")["Policies"]]
    assert names == ["netboot-aabbccddeeff-ipxe", "netboot-aabbccddeeff"]


def test_an_overridden_option_is_kept_off_the_reservation(armed):
    # The rule that shapes all of this: a reservation's option outranks every
    # policy (reservation > scope policy > server policy > scope > server, per
    # option), so leaving 67 on the reservation would make the condition dead and
    # the server's configuration would look perfectly correct while doing it.
    server, sent = _windhcp()
    server.add(armed())
    reservation = _payload_of(sent, "IPAddress")
    ids = [option["Id"] for option in reservation["Options"]]
    assert 67 not in ids, "the conditioned option must come from a policy"
    # Everything no condition touches stays where it was (1 = subnet mask).
    assert 1 in ids


def test_the_base_policy_serves_what_the_reservation_no_longer_can(armed):
    server, sent = _windhcp()
    server.add(armed())
    policies = _payload_of(sent, "Policies")["Policies"]
    conditional, base = policies[0], policies[1]
    assert base["Name"] == "dhcpctl-aabbccddeeff"
    assert base["UserClass"] == "" and base["MacAddress"] == "aabbccddeeff"
    assert base["Options"] == [{"Id": 67, "Value": ["undionly.kpxe"]}]
    # Order is explicit: the conditional policy must be consulted first, or the
    # base one answers an iPXE client and the chainload never happens.
    assert conditional["Order"] < base["Order"]


def test_no_base_policy_when_the_reservation_had_nothing_to_override(armed):
    server, sent = _windhcp()
    server.add(armed(options={"subnet-mask": "255.255.255.0"}))
    names = [p["Name"] for p in _payload_of(sent, "Policies")["Policies"]]
    assert names == ["dhcpctl-aabbccddeeff-ipxe"]


def test_the_netsh_method_also_keeps_the_option_off_the_reservation(armed):
    server, sent = _windhcp("windhcp://dhcp01/?method=netsh")
    server.add(armed())
    commands = _payload_of(sent, "Commands")["Commands"]
    for command in commands:
        if "reservedoptionvalue" in command["Args"]:
            assert "67" not in command["Args"], "67 must come from the policy"


def test_shared_mode_has_one_policy_for_every_client_and_no_base(armed):
    # The netsh-only shape: an administrator creates one policy per condition
    # once, rather than one per machine forever. The option is still kept off
    # the reservation, but the base value is then not this backend's to serve.
    server, sent = _windhcp("windhcp://dhcp01/?conditions=shared")
    server.add(armed())
    policies = _payload_of(sent, "Policies")["Policies"]
    assert [p["Name"] for p in policies] == ["ipxe"]
    assert policies[0]["MacAddress"] == ""
    ids = [o["Id"] for o in _payload_of(sent, "IPAddress")["Options"]]
    assert 67 not in ids


def test_an_unknown_conditions_mode_is_refused():
    with pytest.raises(dhcpctl.ConfigError, match="target or shared"):
        dhcpctl.connect("windhcp://dhcp01/?conditions=global")


def test_completing_a_kept_client_removes_only_its_own_policies(armed):
    server, sent = _windhcp()
    server.complete(armed(completion={"keep": True}))
    names = _payload_of(sent, "Names")["Names"]
    assert names == ["dhcpctl-aabbccddeeff-ipxe", "dhcpctl-aabbccddeeff"]
    assert "Remove-DhcpServerv4Policy" in "\n".join(sent[0][1])


def test_shared_policies_are_never_removed_on_completion(armed):
    server, sent = _windhcp("windhcp://dhcp01/?conditions=shared")
    server.complete(armed(completion={"keep": True}))
    # Only the reservation rewrite; the estate's policy is left alone.
    assert not any("Names" in payload for payload, _ in sent)


def test_windhcp_defines_the_user_class_the_policy_needs(armed):
    # Measured on Windows Server 2025: Add-DhcpServerv4Policy refuses a class it
    # does not know ("The specified User class iPXE does not exist").
    server, sent = _windhcp()
    server.add(armed())
    policy = _payload_of(sent, "Policies")["Policies"][0]
    assert policy["Classes"] == [{"Name": "iPXE", "Type": "User", "Data": "iPXE"}]
    body = "\n".join(sent[0][1])
    assert "Add-DhcpServerv4Class" in body and "Get-DhcpServerv4Class" in body


def test_windhcp_only_creates_a_policy_that_is_absent(armed):
    server, sent = _windhcp()
    server.add(armed())
    body = "\n".join(sent[0][1])
    assert "Get-DhcpServerv4Policy" in body
    assert "if (-not $existing)" in body


def test_windhcp_policies_go_through_the_cmdlets_whatever_the_method(armed):
    # netsh has no policy verb at all (measured), so `method=netsh` still uses
    # the cmdlets for this part and only the reservation goes through netsh.
    server, sent = _windhcp("windhcp://dhcp01/?method=netsh")
    server.add(armed())
    assert "Add-DhcpServerv4Policy" in "\n".join(sent[0][1])
    assert "Commands" in sent[1][0]


def test_windhcp_ensure_condition_creates_just_that_policy(armed, ipxe):
    server, sent = _windhcp()
    assert server.ensure_condition(armed(), ipxe) == "ipxe"
    assert len(sent) == 1
    assert "Policies" in sent[0][0]


@pytest.mark.parametrize("owner", ["dhcpctl", "netboot"])
def test_windhcp_explains_a_host_without_the_dhcpserver_module(armed, owner):
    server, _ = _windhcp(owner=owner)
    # The policy script throws a marker naming the owner; the cmdlets' own
    # errors are localised, so the marker is what is matched.
    marker = f"{owner.upper()}-NO-POLICY-CMDLETS"

    def _no_cmdlets(payload, body):
        if "Policies" in payload:
            assert any(marker in line for line in body)
            raise RuntimeError(marker)

    server.run = _no_cmdlets
    with pytest.raises(dhcpctl.ConditionMissingError) as excinfo:
        server.add(armed())
    message = str(excinfo.value)
    assert "no DhcpServer PowerShell module" in message
    assert f"Add-DhcpServerv4Policy -Name '{owner}-aabbccddeeff-ipxe'" in message
    assert "Add-DhcpServerv4Class" in message
    assert excinfo.value.recipe in message


def test_another_owners_marker_is_not_mistaken_for_a_missing_module(armed):
    server, _ = _windhcp()

    def _other(payload, body):
        raise RuntimeError("NETBOOT-NO-POLICY-CMDLETS")

    server.run = _other
    with pytest.raises(RuntimeError, match="NETBOOT-NO-POLICY-CMDLETS"):
        server.add(armed())


def test_the_windhcp_recipe_is_the_text_the_error_carries(armed, ipxe):
    server, _ = _windhcp()
    recipe = server.condition_recipe(armed(), ipxe)
    assert recipe.startswith("# dhcpctl:")
    # Target mode: the per-target pair that `add` itself would create.
    assert (
        "Add-DhcpServerv4Policy -Name 'dhcpctl-aabbccddeeff-ipxe' -ScopeId $scope "
        "-Condition AND -UserClass EQ,'iPXE' -MacAddress EQ,'aabbccddeeff'"
    ) in recipe
    assert "Add-DhcpServerv4Policy -Name 'dhcpctl-aabbccddeeff' " in recipe
    assert "-ProcessingOrder 1" in recipe and "-ProcessingOrder 2" in recipe
    assert (
        "Set-DhcpServerv4OptionValue -PolicyName 'dhcpctl-aabbccddeeff-ipxe'" in recipe
    )


def test_a_shared_windhcp_recipe_is_one_policy_by_name(armed, ipxe):
    server, _ = _windhcp("windhcp://dhcp01/?conditions=shared")
    recipe = server.condition_recipe(armed(), ipxe)
    assert "Add-DhcpServerv4Policy -Name 'ipxe' -ScopeId $scope" in recipe
    assert "-MacAddress" not in recipe and "-ProcessingOrder" not in recipe


def test_every_value_in_a_windhcp_recipe_is_a_quoted_literal(reservation):
    hostile = "iPXE'; Remove-DhcpServerv4Scope -ScopeId 10.0.0.0 -Force; '"
    smart = "x\u2019; Write-Output INJECTED; \u2019"
    condition = Condition("ipxe", {"user-class": hostile}, {"file": smart})
    server, _ = _windhcp()
    recipe = server.condition_recipe(reservation(), condition)
    assert (
        "EQ,'iPXE''; Remove-DhcpServerv4Scope -ScopeId 10.0.0.0 -Force; '''" in recipe
    )
    assert "'x\u2019\u2019; Write-Output INJECTED; \u2019\u2019'" in recipe


def test_a_shared_policy_that_exists_is_left_as_it_is(armed):
    server, sent = _windhcp("windhcp://dhcp01/?conditions=shared")
    server.add(armed())
    payload, body = next((p, b) for p, b in sent if "Policies" in p)
    assert payload["Shared"] is True
    script = "\n".join(body)
    # Existence is checked before anything is created or set.
    assert script.index("if ($existing -and $p.Shared) { continue }") < script.index(
        "Add-DhcpServerv4Class"
    )
    assert "if (-not $cmdlets -and -not $p.Shared)" in script


def test_removing_a_target_removes_its_own_policies(armed):
    server, sent = _windhcp()
    server.complete(armed())
    names = next(p["Names"] for p, _ in sent if "Names" in p)
    assert names == ["dhcpctl-aabbccddeeff-ipxe", "dhcpctl-aabbccddeeff"]


def test_removing_a_shared_target_leaves_the_estates_policies(armed):
    server, sent = _windhcp("windhcp://dhcp01/?conditions=shared")
    server.complete(armed())
    assert not any("Names" in p for p, _ in sent)


# -- dhcpd: an inline `if`, or a group -------------------------------------


class _FakeOmapi:
    def __init__(self, calls):
        self.calls = calls

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.calls.append((name, args, kwargs))

        return record


def _dhcpd(uri="dhcpd://dhcp01/", **kwargs):
    server = dhcpctl.connect(uri, **kwargs)
    calls = []
    server.omapi = lambda: _FakeOmapi(calls)
    return server, calls


def _created(calls):
    """The keyword arguments of the `create_host` call."""
    return next(call[2] for call in calls if call[0] == "create_host")


def test_dhcpd_inlines_the_conditional_by_default(armed):
    server, calls = _dhcpd()
    server.add(armed())
    statements = _created(calls)["statements"]
    assert 'filename "undionly.kpxe";' in statements
    assert 'if exists user-class and option user-class = "iPXE"' in statements
    # The unconditional option comes first, so the conditional overrides it.
    assert statements.index("undionly.kpxe") < statements.index("user-class")
    assert not any(call[0] == "add_group" for call in calls)


def test_a_condition_next_server_is_a_statement_inside_its_if(armed):
    server, calls = _dhcpd()
    conditions = {
        "ipxe": Condition(
            "ipxe",
            {"user-class": "iPXE"},
            {"file": "boot.ipxe", "next-server": "10.0.0.3"},
        )
    }
    server.add(armed(conditions=conditions, next_server="10.0.0.2"))
    statements = _created(calls)["statements"]
    assert statements == (
        'option subnet-mask 255.255.255.0; filename "undionly.kpxe"; '
        "next-server 10.0.0.2; "
        'if exists user-class and option user-class = "iPXE" '
        '{ filename "boot.ipxe"; next-server 10.0.0.3; }'
    )


def test_dhcpd_ensure_condition_needs_nothing_created(armed, ipxe):
    server, calls = _dhcpd()
    assert server.ensure_condition(armed(), ipxe) == "ipxe"
    assert calls == []


def test_dhcpd_group_mode_creates_the_group_and_attaches_the_host(armed):
    server, calls = _dhcpd("dhcpd://dhcp01/?conditions=group")
    server.add(armed())
    names = [call[0] for call in calls]
    # Re-arming replaces a host, so the create follows a delete.
    assert names == ["group_exists", "add_group", "del_host", "create_host", "close"]
    assert calls[1][1][0] == "ipxe"
    assert "if exists user-class" in calls[1][1][1]
    # The host is created in its group: never a moment without its condition.
    assert _created(calls)["group"] == "ipxe"
    # The host's own boot file applies only where the group's condition does not.
    assert _created(calls)["statements"].startswith("option subnet-mask")
    assert (
        'if (exists user-class and option user-class = "iPXE") { } else '
        '{ filename "undionly.kpxe"; }'
    ) in _created(calls)["statements"]


def test_dhcpd_group_mode_names_one_group_for_several_conditions(armed):
    server, calls = _dhcpd("dhcpd://dhcp01/?conditions=group")
    conditions = dict(IPXE)
    conditions["winpe"] = {
        "match": {"vendor-class": "PXEClient:Arch:00000"},
        "options": {"file": "wdsnbp.com"},
    }
    server.add(armed(conditions=conditions))
    # A host belongs to exactly one group, so one group carries both.
    assert calls[1][0] == "add_group" and calls[1][1][0] == "ipxe-winpe"
    assert _created(calls)["group"] == "ipxe-winpe"


def test_dhcpd_group_mode_uses_a_group_that_is_already_there(armed):
    server, calls = _dhcpd("dhcpd://dhcp01/?conditions=group")

    class _Existing(_FakeOmapi):
        def group_exists(self, name):
            return True

    server.omapi = lambda: _Existing(calls)
    server.add(armed())
    assert [call[0] for call in calls] == ["del_host", "create_host", "close"]


def test_dhcpd_group_mode_arms_nothing_when_the_group_cannot_be_made(armed):
    server, calls = _dhcpd("dhcpd://dhcp01/?conditions=group")

    class _Refused(_FakeOmapi):
        def add_group(self, name, statements):
            raise RuntimeError("add group failed")

    server.omapi = lambda: _Refused(calls)
    with pytest.raises(dhcpctl.ServerError, match="refused to create group 'ipxe'"):
        server.add(armed())
    # No host without its condition, and the connection is closed.
    assert [call[0] for call in calls] == ["group_exists", "close"]


def test_dhcpd_completion_drops_the_host_out_of_its_group(armed):
    server, calls = _dhcpd("dhcpd://dhcp01/?conditions=group")
    server.complete(armed(completion={"keep": True}))
    # Created again without a group, then again with the kept options.
    names = [call[0] for call in calls if call[0] != "close"]
    assert names == ["del_host", "create_host", "del_host", "create_host"]
    created = [call[2] for call in calls if call[0] == "create_host"]
    assert all(not c.get("group") for c in created)
    assert "undionly.kpxe" in created[0]["statements"]
    assert "undionly.kpxe" not in created[1]["statements"]


def test_dhcpd_inline_mode_has_no_membership_to_drop(armed, ipxe):
    server, calls = _dhcpd()
    server.remove_condition_member(armed(), ipxe)
    assert calls == []


def test_dhcpd_refuses_a_match_value_that_would_escape_its_test():
    from dhcpctl.backends._dhcpd import render_condition

    condition = Condition(
        "evil", {"user-class": 'x" { filename "pwned"; } #'}, {"file": "y"}
    )
    with pytest.raises(dhcpctl.ConfigError, match="quote cannot appear"):
        render_condition(condition)


def test_an_unknown_dhcpd_conditions_mode_is_refused():
    with pytest.raises(dhcpctl.ConfigError, match="must be 'if' or 'group'"):
        dhcpctl.connect("dhcpd://dhcp01/?conditions=policies")


def test_the_dhcpd_recipe_is_a_config_group(armed, ipxe):
    server, _ = _dhcpd()
    recipe = server.condition_recipe(armed(), ipxe)
    assert recipe.startswith("# dhcpctl:")
    assert 'group "ipxe" {' in recipe
    assert "need not be created over OMAPI" in recipe


# -- kea: a client class ---------------------------------------------------


def _kea(class_exists=False, **kwargs):
    server = dhcpctl.connect("kea://ctrl01/", **kwargs)
    sent = []

    def command(cmd, arguments=None):
        sent.append((cmd, arguments))
        if cmd == "class-get":
            return {"result": 0 if class_exists else 3}
        return {"result": 0}

    server.command = command
    return server, sent


CLIENT = "aabbccddeeff"


def test_kea_updates_this_clients_class_when_it_exists(armed):
    server, sent = _kea(class_exists=True)
    server.add(armed())
    assert [cmd for cmd, _ in sent] == [
        "class-get",
        "class-update",
        "class-get",
        "class-update",
        "reservation-add",
    ]


def test_kea_adds_this_clients_classes_when_it_can(armed):
    server, sent = _kea(class_exists=False)
    server.add(armed())
    assert [cmd for cmd, _ in sent] == [
        "class-get",
        "class-add",
        "class-get",
        "class-add",
        "reservation-add",
    ]
    condition = dict(sent[1][1])["client-classes"][0]
    assert condition["name"] == f"ipxe-{CLIENT}"
    assert condition["test"] == f"pkt4.mac == 0x{CLIENT} and option[77].hex == 'iPXE'"
    # The boot file is the class's header field, as on a reservation.
    assert condition["boot-file-name"] == "boot.ipxe"
    assert "option-data" not in condition
    # What the condition overrides is served by a class of the client's that
    # matches when it does not; the rest stays in the reservation.
    base = dict(sent[3][1])["client-classes"][0]
    assert base["name"] == f"dhcpctl-{CLIENT}"
    assert base["test"] == f"pkt4.mac == 0x{CLIENT} and not member('ipxe-{CLIENT}')"
    assert base["boot-file-name"] == "undionly.kpxe" and "option-data" not in base
    reservation = dict(sent[4][1])["reservation"]
    assert "boot-file-name" not in reservation
    assert "client-classes" not in reservation
    assert reservation["option-data"] == [{"code": 1, "data": "255.255.255.0"}]


def test_a_kea_class_spells_reservation_fields_as_options(reservation):
    # A class has no reservation fields: hostname stays option 12 and a
    # numeric option keeps its code. next-server is the class's own field.
    from dhcpctl.backends._kea import _class

    condition = Condition(
        "c",
        {"user-class": "iPXE", "vendor-class": "PXEClient"},
        {"next-server": "10.0.0.2", "hostname": "h", "option-252": "x"},
    )
    entry = _class(condition, reservation())
    assert entry["test"] == (
        f"pkt4.mac == 0x{CLIENT} and option[77].hex == 'iPXE' and "
        "option[60].hex == 'PXEClient'"
    )
    assert entry["option-data"] == [
        {"code": 12, "data": "h"},
        {"code": 252, "data": "x"},
    ]
    assert entry["next-server"] == "10.0.0.2"


def test_a_kea_class_without_next_server_has_no_such_field(reservation):
    from dhcpctl.backends._kea import _class

    entry = _class(Condition("c", {"user-class": "iPXE"}, {"file": "x"}), reservation())
    assert "next-server" not in entry


def test_a_condition_next_server_reaches_the_kea_class_add(armed):
    server, sent = _kea(class_exists=False)
    conditions = {
        "ipxe": Condition(
            "ipxe",
            {"user-class": "iPXE"},
            {"file": "boot.ipxe", "next-server": "10.0.0.3"},
        )
    }
    server.add(armed(conditions=conditions, next_server="10.0.0.2"))
    entry = dict(sent[1][1])["client-classes"][0]
    assert entry["next-server"] == "10.0.0.3"
    assert entry["boot-file-name"] == "boot.ipxe"
    # Kea serves a reservation's values over any class's, so the client's
    # own next-server is its base class's, not the reservation's.
    assert dict(sent[3][1])["client-classes"][0]["next-server"] == "10.0.0.2"
    assert "next-server" not in dict(sent[4][1])["reservation"]


def test_a_condition_that_overrides_nothing_set_needs_no_base_class(armed):
    server, sent = _kea(class_exists=False)
    server.add(armed(options={"subnet-mask": "255.255.255.0"}))
    assert [cmd for cmd, _ in sent] == ["class-get", "class-add", "reservation-add"]


def test_leaving_a_condition_deletes_the_base_class_first(armed):
    server, sent = _kea(class_exists=True)
    server.remove_condition_member(armed(), armed().conditions["ipxe"])
    assert sent == [
        ("class-del", {"name": f"dhcpctl-{CLIENT}"}),
        ("class-del", {"name": f"ipxe-{CLIENT}"}),
    ]


def test_removing_a_client_removes_its_classes(armed):
    server, sent = _kea(class_exists=True)
    server.remove(armed())
    assert [cmd for cmd, _ in sent] == ["reservation-del", "class-del", "class-del"]


@pytest.mark.parametrize("owner", ["dhcpctl", "netboot"])
def test_kea_without_the_class_cmds_hook_hands_over_the_json(armed, owner):
    server = dhcpctl.connect("kea://ctrl01/", owner=owner)

    def command(cmd, arguments=None):
        if cmd == "class-get":
            return {"result": 3}
        if cmd == "class-add":
            return {"result": 2}  # unsupported command: hook not loaded
        return {"result": 0}

    server.command = command
    with pytest.raises(dhcpctl.ConditionMissingError) as excinfo:
        server.add(armed())
    message = str(excinfo.value)
    assert "class_cmds" in message
    assert f"so {owner} cannot add one" in message
    assert excinfo.value.recipe.startswith(f"// {owner}:")
    first, base = excinfo.value.recipe.split("\n", 1)[1].split("\n}\n")
    assert json.loads(first + "\n}")["name"] == f"ipxe-{CLIENT}"
    assert json.loads(base)["name"] == f"{owner}-{CLIENT}"


def test_kea_reports_another_class_add_failure(armed):
    server = dhcpctl.connect("kea://ctrl01/")
    server.command = lambda cmd, arguments=None: (
        {"result": 3} if cmd == "class-get" else {"result": 1, "text": "bad test"}
    )
    with pytest.raises(dhcpctl.ServerError, match="bad test"):
        server.add(armed())


def test_a_kea_test_cannot_be_escaped_by_a_match_value(reservation):
    from dhcpctl.backends._kea import _class

    condition = Condition("evil", {"user-class": "x' or 'a'=='a"}, {"file": "y"})
    with pytest.raises(dhcpctl.ConfigError, match="quote or newline"):
        _class(condition, reservation())


# -- dnsmasq: refuses ------------------------------------------------------


def test_dnsmasq_refuses_a_condition_with_the_reason_and_the_recipe(tmp_path, armed):
    hosts = tmp_path / "h"
    hosts.mkdir()
    server = dhcpctl.connect(f"dnsmasq:///?hostsfile={hosts.as_posix()}")
    with pytest.raises(dhcpctl.ConditionUnsupportedError) as excinfo:
        server.add(armed())
    message = str(excinfo.value)
    assert "dhcp-match" in message and "dhcp-optsfile" in message
    assert "dhcp-match=set:ipxe,77,iPXE" in message
    assert "which dhcpctl does not write" in message


def test_the_dnsmasq_recipe_is_the_match_and_option_pair(tmp_path, armed, ipxe):
    hosts = tmp_path / "h"
    hosts.mkdir()
    server = dhcpctl.connect(f"dnsmasq:///?hostsfile={hosts.as_posix()}")
    recipe = server.condition_recipe(armed(), ipxe)
    assert recipe.split("\n  ") == [
        "dhcp-match=set:ipxe,77,iPXE",
        "dhcp-option=tag:ipxe,option:bootfile-name,boot.ipxe",
    ]


def test_dnsmasq_writes_nothing_when_it_refuses(tmp_path, armed):
    hosts = tmp_path / "h"
    hosts.mkdir()
    server = dhcpctl.connect(f"dnsmasq:///?hostsfile={hosts.as_posix()}")
    with pytest.raises(dhcpctl.ConditionUnsupportedError):
        server.add(armed())
    assert list(hosts.iterdir()) == [], "a refusal must not half-apply"


def test_the_dnsmasq_recipe_carries_a_next_server_in_dhcp_boot():
    from dhcpctl.backends import DnsmasqBackend

    server = DnsmasqBackend("dnsmasq:///?hostsfile=/tmp/h/")
    condition = Condition(
        "ipxe",
        {"user-class": "iPXE"},
        {"file": "boot.ipxe", "next-server": "10.0.0.2"},
    )
    recipe = server.condition_recipe(None, condition)
    assert recipe.split("\n  ") == [
        "dhcp-match=set:ipxe,77,iPXE",
        "dhcp-option=tag:ipxe,option:bootfile-name,boot.ipxe",
        "dhcp-option=tag:ipxe,option:server-ip-address,10.0.0.2",
    ]
