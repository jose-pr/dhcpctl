"""`dhcpctl render`: what an operation would send, with nothing contacted."""

from __future__ import annotations

import sys
import typing as _ty

from ._common import ReservationCommand

__all__ = ["Render"]


class Render(ReservationCommand):
    """Print what arming, keeping or removing would send the server, contacting nothing."""

    _parsername_ = "render"
    _examples_ = [
        (
            "dhcpctl render 'dhcpd://dhcp01/' -n web01 -m aa:bb:cc:dd:ee:ff "
            "--ip 10.0.0.10 -o router=10.0.0.1 -o file=undionly.kpxe",
            "the OMAPI calls arming web01 would make",
        ),
        ("dhcpctl render 'kea://kea01/' --from web01.yaml -a remove", "a removal"),
    ]

    action: _ty.Literal["add", "keep", "complete", "remove"] = "add"
    "The operation to show"
    ("--action", "-a")

    def __call__(self) -> int:
        server = self.server()
        sys.stdout.write(server.render(self.reservation(server), self.action))
        return 0
