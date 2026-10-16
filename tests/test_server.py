"""The `DHCPServer` contract every backend shares.

`complete` and `extras` are implemented once, in the base class, and the base
refuses what a backend has not said it can do (keep an entry, serve a
condition) rather than quietly doing nothing.

The `extras()` extension point's worked example is the iPXE chainload: a PXE ROM
must be handed the iPXE binary, and iPXE itself must then be handed the script,
or it loads itself forever. No backend models that, so each one has to be told
in its own language -- from the URI (`raw.<scheme>`), from the reservation, or
from a subclass that can see the client.
"""

import pytest

import dhcpctl
from dhcpctl import PHASES, DHCPServer

#: What dhcpd is told, in its own language, to chainload iPXE.
IPXE_DHCPD = (
    'if exists user-class and option user-class = "iPXE" '
    '{ filename "boot.ipxe"; } else { filename "undionly.kpxe"; }'
)

IPXE = {
    "ipxe": {
        "match": {"user-class": "iPXE"},
        "options": {"boot-file-name": "boot.ipxe"},
    }
}
WINPE = {
    "winpe": {
        "match": {"vendor-class": "PXEClient:Arch:00000"},
        "options": {"boot-file-name": "wdsnbp.com"},
    }
}


class _Recording(DHCPServer):
    """A backend that records what the shared code asks of it, in order."""

    def __init__(self, uri="rec://host/", **kwargs):
        super().__init__(uri, **kwargs)
        self.calls = []

    def add(self, reservation):
        self.calls.append("add")

    def remove(self, reservation):
        self.calls.append("remove")

    def keep(self, reservation):
        self.calls.append("keep")

    def remove_condition_member(self, reservation, condition):
        self.calls.append(f"detach:{condition.name}")


# -- complete() ------------------------------------------------------------


def test_complete_removes_by_default(reservation):
    server = _Recording()
    server.complete(reservation(conditions=IPXE))
    # Deleting the entry drops the membership with it: nothing to detach.
    assert server.calls == ["remove"]


def test_a_kept_entry_leaves_every_condition_before_it_is_kept(reservation):
    # Otherwise the condition keeps serving the installer to a finished machine,
    # which is completion's own failure arriving through the other feature.
    server = _Recording()
    server.complete(
        reservation(conditions={**IPXE, **WINPE}, completion={"keep": True})
    )
    assert server.calls == ["detach:ipxe", "detach:winpe", "keep"]


def test_a_backend_that_cannot_keep_says_so(reservation):
    class CannotKeep(DHCPServer):
        def remove(self, reservation):
            pass

    with pytest.raises(NotImplementedError, match="cannot keep a reservation"):
        CannotKeep("cannotkeep://host/").complete(
            reservation(completion={"keep": True})
        )


def test_the_base_add_and_remove_do_nothing(reservation):
    server = DHCPServer("base://host/")
    assert server.add(reservation()) is None
    assert server.remove(reservation()) is None


# -- conditions ------------------------------------------------------------


def test_a_backend_that_says_nothing_about_conditions_refuses_them(reservation, ipxe):
    server = DHCPServer("silent://host/")
    with pytest.raises(
        dhcpctl.ConditionUnsupportedError, match="cannot serve conditional"
    ):
        server.ensure_condition(reservation(), ipxe)
    # ... has no recipe to offer, and nothing to detach, which must not raise.
    assert server.condition_recipe(reservation(), ipxe) == ""
    assert server.remove_condition_member(reservation(), ipxe) is None


def test_the_error_types_are_one_family():
    for error in (
        dhcpctl.ConfigError,
        dhcpctl.UnknownBackendError,
        dhcpctl.BackendUnavailableError,
        dhcpctl.MissingMACError,
        dhcpctl.ServerError,
        dhcpctl.ReservationExistsError,
        dhcpctl.ConditionUnsupportedError,
        dhcpctl.ConditionMissingError,
    ):
        assert issubclass(error, dhcpctl.DHCPCtlError)
    assert issubclass(dhcpctl.ReservationExistsError, dhcpctl.ServerError)
    assert issubclass(dhcpctl.MissingMACError, LookupError)


def test_a_missing_condition_carries_its_recipe():
    error = dhcpctl.ConditionMissingError("absent", "do this")
    assert error.recipe == "do this"
    assert str(error) == "absent\n\ndo this"
    assert str(dhcpctl.ConditionMissingError("absent")) == "absent"


# -- the client --------------------------------------------------------------


def test_a_missing_or_null_mac_is_named(reservation):
    for mac in (None, "00:00:00:00:00:00"):
        target = reservation(mac=mac).target
        with pytest.raises(dhcpctl.MissingMACError, match="'web01'.*the reason"):
            target.require_mac("the reason")


def test_a_client_without_an_address_has_empty_ip_text(reservation):
    assert reservation(ip=None).target.ip_text == ""
    assert reservation().target.ip_text == "10.0.0.10"


# -- extras() ----------------------------------------------------------------


def test_extras_defaults_to_the_configured_raw_lines(reservation):
    server = dhcpctl.connect("dhcpd://dhcp01/?raw.dhcpd=" + "log(concat(1));")
    assert server.extras(reservation(), "add") == ["log(concat(1));"]
    # A bare `raw.<scheme>` belongs to arming, not teardown.
    assert server.extras(reservation(), "remove") == []


def test_a_raw_fragment_can_name_the_teardown_phase(reservation):
    server = dhcpctl.connect("dhcpd://dhcp01/?raw.dhcpd.remove=" + "log(concat(2));")
    assert server.extras(reservation(), "add") == []
    assert server.extras(reservation(), "remove") == ["log(concat(2));"]


def test_both_phases_can_be_given_at_once(reservation):
    server = dhcpctl.connect(
        "dhcpd://dhcp01/?raw.dhcpd=a;&raw.dhcpd.add=b;&raw.dhcpd.remove=c;"
    )
    # The unsuffixed one first: it was written as "the" fragment.
    assert server.extras(reservation(), "add") == ["a;", "b;"]
    assert server.extras(reservation(), "remove") == ["c;"]


def test_raw_fragments_for_another_scheme_are_ignored(reservation):
    server = dhcpctl.connect("dhcpd://dhcp01/?raw.dnsmasq=x")
    assert server.extras(reservation(), "add") == []


def test_the_reservation_extras_follow_the_uri_ones(reservation):
    server = dhcpctl.connect("dhcpd://dhcp01/?raw.dhcpd=a;&raw.dhcpd.remove=c;")
    r = reservation(extras={"add": ["b;"], "remove": ["d;"]})
    assert server.extras(r, "add") == ["a;", "b;"]
    assert server.extras(r, "remove") == ["c;", "d;"]


def test_an_unknown_phase_is_refused(reservation):
    server = dhcpctl.connect("dhcpd://dhcp01/")
    with pytest.raises(ValueError, match="phase must be one of"):
        server.extras(reservation(), "bootstrap")
    assert PHASES == ("add", "remove")


def test_a_subclass_can_decide_per_client(reservation):
    # The hook's reason for existing: a URI cannot look at the client, and
    # `context` is the caller's own description of it.
    class Ipxe(DHCPServer):
        applied: list = []

        def extras(self, reservation, phase="add"):
            lines = super().extras(reservation, phase)
            if phase == "add" and reservation.context == {"image": "debian"}:
                lines.append(IPXE_DHCPD)
            return lines

        def add(self, reservation):
            Ipxe.applied = self.extras(reservation, "add")

    server = Ipxe("ipxe://host/?raw.ipxe=" + "authoritative;")
    server.add(reservation(context={"image": "debian"}))
    assert Ipxe.applied == ["authoritative;", IPXE_DHCPD]
    server.add(reservation(context={"image": "windows"}))
    assert Ipxe.applied == ["authoritative;"]
