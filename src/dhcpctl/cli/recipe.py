"""`dhcpctl recipe`: the server-side setup a reservation's conditions need."""

from __future__ import annotations

from duho import UsageError

from ._common import ReservationCommand

__all__ = ["Recipe"]


class Recipe(ReservationCommand):
    """Print, per condition, what an administrator adds to the server once; contacts nothing."""

    _parsername_ = "recipe"

    def __call__(self) -> int:
        server = self.server()
        reservation = self.reservation(server)
        if not reservation.conditions:
            raise UsageError(
                "the reservation has no conditions; describe them in a --from document"
            )
        for condition in reservation.conditions.values():
            print(server.condition_recipe(reservation, condition))
            print()
        return 0
