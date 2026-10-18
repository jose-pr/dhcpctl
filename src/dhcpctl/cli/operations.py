"""`dhcpctl add`, `complete` and `remove`: the operations that change a server."""

from __future__ import annotations

import dataclasses

from .._model import Completion
from ._common import ReservationCommand

__all__ = ["Add", "Complete", "Remove"]


class Add(ReservationCommand):
    """Arm a client's reservation, replacing what the server holds for it."""

    _parsername_ = "add"

    def __call__(self) -> int:
        server = self.server()
        reservation = self.reservation(server)
        server.add(reservation)
        print(f"armed {reservation.target.name} on {server}")
        return 0


class Complete(ReservationCommand):
    """Finish a client: remove its reservation, or with --keep keep it without its boot options."""

    _parsername_ = "complete"

    keep: bool = False
    "Keep the reservation, dropping its boot file, next server and conditions"
    ("--keep",)

    def __call__(self) -> int:
        server = self.server()
        reservation = self.reservation(server)
        if self.keep and not reservation.completion.keep:
            reservation = dataclasses.replace(
                reservation, completion=Completion(keep=True)
            )
        server.complete(reservation)
        done = "kept" if reservation.completion.keep else "removed"
        print(f"{done} {reservation.target.name} on {server}")
        return 0


class Remove(ReservationCommand):
    """Remove a client's reservation; one that is not there is not an error."""

    _parsername_ = "remove"

    def __call__(self) -> int:
        server = self.server()
        reservation = self.reservation(server)
        server.remove(reservation)
        print(f"removed {reservation.target.name} from {server}")
        return 0
