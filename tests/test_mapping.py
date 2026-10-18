"""Reservations, conditions and completions as plain data and documents.

The mapping a reservation writes is the one it reads back, to an equal
reservation; what is served is pydhcp's own `DHCPLease.to_mapping` form, for
the reservation, each condition and the completion alike.
"""

from __future__ import annotations

import ipaddress

import pytest
from netimps import MACAddress

import dhcpctl
from dhcpctl import Completion, Reservation, Scope, Target, parse_conditions

CODES = dhcpctl.option_codes({"site": {"code": 224, "type": "String"}})


def full() -> Reservation:
    lease = CODES.lease(
        {
            "router": "10.0.0.1",
            "site": "rack-4",
            "option-250": "0a0b",
            "file": "undionly.kpxe",
            "next-server": "10.0.0.2",
        }
    )
    return Reservation(
        Target("pc1", mac=MACAddress("aa:bb:cc:dd:ee:ff")),
        Scope("lab", network=ipaddress.ip_network("10.0.0.0/24"), subnet_id=3),
        lease.replace(ip="10.0.0.5"),
        conditions=parse_conditions(
            {
                "ipxe": {
                    "match": {"user-class": "iPXE"},
                    "options": {"file": "boot.ipxe", "next-server": "10.0.0.3"},
                }
            },
            "pc1",
            CODES,
        ),
        completion=Completion(True, {"file": "local"}, codes=CODES),
        extras={"add": ["# pc1"]},
    )


def test_a_reservation_writes_every_part_it_holds():
    assert full().to_mapping() == {
        "target": {"name": "pc1", "mac": "aa:bb:cc:dd:ee:ff"},
        "scope": {"name": "lab", "network": "10.0.0.0/24", "subnet-id": 3},
        "lease": {
            "ip": "10.0.0.5",
            "offered": False,
            "siaddr": "10.0.0.2",
            "file": "undionly.kpxe",
            "options": {"ROUTER": ["10.0.0.1"], "SITE": "rack-4", "250": "0a0b"},
        },
        "conditions": {
            "ipxe": {
                "match": {"user-class": "iPXE"},
                "lease": {
                    "ip": "0.0.0.0",
                    "offered": False,
                    "siaddr": "10.0.0.3",
                    "file": "boot.ipxe",
                    "options": {},
                },
            }
        },
        "completion": {
            "keep": True,
            "lease": {
                "ip": "0.0.0.0",
                "offered": False,
                "file": "local",
                "options": {},
            },
        },
        "extras": {"add": ["# pc1"]},
    }


def test_an_unset_part_is_left_out():
    assert Reservation(Target("pc1")).to_mapping() == {
        "target": {"name": "pc1"},
        "lease": {"ip": "0.0.0.0", "offered": False, "options": {}},
    }


def test_a_mapping_reads_back_to_an_equal_reservation():
    reservation = full()
    assert (
        Reservation.from_mapping(reservation.to_mapping(), codes=CODES) == reservation
    )


def test_only_the_target_name_is_required():
    reservation = Reservation.from_mapping({"target": {"name": "pc1"}})
    assert reservation == Reservation(Target("pc1"))
    assert reservation.lease.ip == dhcpctl.UNSPECIFIED


@pytest.mark.parametrize("format", ["json", "yaml", "toml", "ini"])
def test_a_document_reads_back_to_an_equal_reservation(format):
    if format != "json":
        pytest.importorskip("pktcap")
    reservation = full()
    text = reservation.to_text(format)
    assert Reservation.from_text(text, format, codes=CODES) == reservation


@pytest.mark.parametrize(
    "data, message",
    [
        ({}, "target must be a mapping"),
        ({"target": {}}, "needs a `name`"),
        ({"target": {"name": "a"}, "options": {}}, "unknown key"),
        ({"target": {"name": "a", "ip": "10.0.0.5"}}, "target has unknown key"),
        ({"target": {"name": "a", "mac": "nope"}}, "reservation 'a'"),
        ({"target": {"name": "a"}, "lease": {"ip": "fe80::1"}}, "reservation a"),
        ({"target": {"name": "a"}, "lease": {"options": {"nosuch": 1}}}, "nosuch"),
        ({"target": {"name": "a"}, "lease": {"siaddr": "x"}}, "siaddr"),
        ({"target": {"name": "a"}, "extras": {"apply": []}}, "extras has unknown"),
        ({"target": {"name": "a"}, "extras": {"add": "x"}}, "must be a list"),
        (
            {"target": {"name": "a"}, "completion": {"options": {"router": "1.1.1.1"}}},
            "not `keep: true`",
        ),
    ],
)
def test_a_mapping_that_cannot_be_read_is_a_config_error(data, message):
    with pytest.raises(dhcpctl.ConfigError, match=message):
        Reservation.from_mapping(data)


def test_a_condition_writes_the_entry_parse_conditions_reads():
    condition = full().conditions["ipxe"]
    again = parse_conditions({"ipxe": condition.to_mapping()}, "pc1", CODES)
    assert again == {"ipxe": condition}


def test_a_removing_completion_writes_only_keep():
    assert Completion().to_mapping() == {"keep": False}
    assert Completion() == Completion()
    assert Completion(True) != Completion()
