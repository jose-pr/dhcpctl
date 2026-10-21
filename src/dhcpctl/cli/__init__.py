"""The `dhcpctl` command line, built on `duho`.

`main` is the entry point of the `dhcpctl` console script and of `python -m
dhcpctl`. It needs the `cli` extra (`pip install pydhcpctl[cli]`); importing this
package does not, so a bare install gets one line naming the extra instead of
an `ImportError`.
"""

from __future__ import annotations

from typing import Optional, Sequence

__all__ = ["main"]

#: What a user who ran the console script without the extra needs to be told.
_NEEDS_EXTRA = (
    "dhcpctl: the command line needs the 'cli' extra -- pip install 'pydhcpctl[cli]'"
)


def main(argv: "Optional[Sequence[str]]" = None) -> int:
    """Run the command line and return its exit status.

    `0` done, `1` the server refused or could not be reached, `2` the
    invocation or the reservation was wrong. A usage error from the parser
    raises `SystemExit` with `2`.
    """
    try:
        import duho
    except ImportError as exc:
        raise SystemExit(_NEEDS_EXTRA) from exc

    from ._root import Dhcpctl

    return duho.run(Dhcpctl, argv, exit="parse")
